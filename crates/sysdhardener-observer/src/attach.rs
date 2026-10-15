//! Independent-observer attach: capture a running process's tree.
//!
//! The production interposition fork (deferred doc option 1) is the
//! independent observer: it does not spawn or modify the target — it
//! attaches to an already-running process (e.g. a systemd-managed
//! unit), follows its whole tree, and attributes the evidence to the
//! target's cgroup. This module implements the attach via
//! `PTRACE_SEIZE`; the eBPF cgroup-attached mechanism (root-only)
//! remains the deferred future swap.

use sysdhardener_core::ObservedEvent;

use super::capture::OBSERVE_LOCK;
use super::capture::ObserveError;
use super::capture::TraceMode;
use super::capture::run_trace_loop;
use super::signal::install_forward_handlers;

/// Attach to an already-running process (`pid`) and capture the
/// address-family and capability-relevant syscalls of its whole
/// process tree.
///
/// This is the **independent observer** interposition (the deferred
/// comparison's option 1, made real without the root-only eBPF
/// mechanism): the target is not spawned by this tool and keeps its
/// systemd-managed identity; the observer attaches via
/// `PTRACE_SEIZE`, follows every fork/vfork/clone, and detaches when
/// the target exits. Requires the ptrace permission (same-UID
/// descendant, or root; Yama `ptrace_scope` permits descendants);
/// the target runs to completion and is never modified.
///
/// # Errors
/// Returns [`ObserveError`] when the attach fails (target not found,
/// no ptrace permission) or the wait loop hits an unexpected state.
pub fn observe_pid(pid: libc::pid_t) -> Result<Vec<ObservedEvent>, ObserveError> {
    observe_pid_with_duration(pid, None)
}

/// Attach to an already-running process (`pid`) and capture syscalls
/// for up to `duration_ms` milliseconds (or until target exit if `None`).
///
/// # Errors
/// Returns [`ObserveError`] when the attach fails or the wait loop hits
/// an unexpected state.
pub fn observe_pid_with_duration(
    pid: libc::pid_t,
    duration_ms: Option<u64>,
) -> Result<Vec<ObservedEvent>, ObserveError> {
    let _guard = OBSERVE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _sig_guard = install_forward_handlers();
    let attached = attach_to_pid(pid)?;
    run_trace_loop(&attached, TraceMode::Attach, duration_ms).map(|capture| capture.events)
}

/// Enumerate all active thread IDs (TIDs) for a process from `/proc/<pid>/task/`.
/// Falls back to returning just `[pid]` if the directory cannot be read.
fn enumerate_threads(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let task_dir = format!("/proc/{pid}/task");
    let mut tids = Vec::new();
    if let Ok(entries) = std::fs::read_dir(task_dir) {
        for entry in entries.flatten() {
            if let Ok(tid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() {
                tids.push(tid);
            }
        }
    }
    if !tids.contains(&pid) {
        tids.push(pid);
    }
    tids.sort_unstable();
    tids
}

/// Attach to an existing process and all its active threads with `PTRACE_SEIZE`
/// and interrupt them cleanly with `PTRACE_INTERRUPT` (avoiding disruptive
/// `SIGSTOP` group-stop signals).
fn attach_to_pid(pid: libc::pid_t) -> Result<Vec<libc::pid_t>, ObserveError> {
    if pid <= 0 {
        return Err(ObserveError::Wait(format!(
            "invalid pid {pid}; must be positive"
        )));
    }
    let mut tids = enumerate_threads(pid);
    tids.retain(|&t| t != pid);
    tids.insert(0, pid);
    let mut attached: Vec<libc::pid_t> = Vec::new();

    for &tid in &tids {
        // SAFETY: PTRACE_SEIZE attaches to an existing thread without
        // stopping it; the tracer becomes the tracee's tracer. EPERM
        // means no ptrace permission (different UID, missing CAP_SYS_PTRACE).
        let rc: libc::c_long = unsafe {
            libc::ptrace(
                libc::PTRACE_SEIZE,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                libc::PTRACE_O_TRACESYSGOOD
                    | libc::PTRACE_O_TRACEFORK
                    | libc::PTRACE_O_TRACEVFORK
                    | libc::PTRACE_O_TRACECLONE
                    | libc::PTRACE_O_TRACEEXEC,
            )
        };
        if rc < 0 {
            let errno: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if tid != pid && errno == libc::ESRCH {
                // A non-leader thread exited between enumeration and seize; safely ignore it.
                continue;
            }
            for &att in &attached {
                unsafe {
                    let mut status = 0;
                    for _ in 0..500 {
                        let w = libc::waitpid(att, &raw mut status, libc::__WALL | libc::WNOHANG);
                        if w == att || w < 0 {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        att,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    );
                }
            }
            return Err(ObserveError::Wait(format!(
                "PTRACE_SEIZE failed (errno {errno}); the target may not be traceable by this user"
            )));
        }

        // SAFETY: PTRACE_INTERRUPT generates a ptrace-stop without sending a
        // signal to the tracee, avoiding unwanted group-stop side-effects.
        let _ = unsafe {
            libc::ptrace(
                libc::PTRACE_INTERRUPT,
                tid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        attached.push(tid);
    }
    Ok(attached)
}

/// Extract the systemd unit name from a cgroup path.
///
/// On a systemd host a unit's cgroup is `system.slice/<unit>.service`
/// (or `user.slice/.../app.slice/<unit>.service` for user units). The
/// unit name is the path component ending in `.service`. Returns
/// `None` when no such component is present (e.g. a non-systemd
/// hierarchy or a scope/session).
///
/// This is the "which systemd unit does this evidence belong to"
/// mapping the production observer needs: the cgroup path is the
/// attribution unit systemd sandboxes, and the unit name is the
/// human/systemd-API handle for it.
#[must_use]
pub fn systemd_unit_from_cgroup(cgroup: &str) -> Option<&str> {
    cgroup
        .trim_end_matches('/')
        .rsplit('/')
        .find(|component| component.ends_with(".service"))
}
