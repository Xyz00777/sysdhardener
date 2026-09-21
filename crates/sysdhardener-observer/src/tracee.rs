//! Tracee process state and tree management.
//!
//! Extracted from `capture.rs` and `ptrace_abi.rs` to keep both
//! modules under the 250 pure-LOC ceiling. These functions manage
//! the traced child processes: options setup, signal delivery,
//! fork/clone following, and clean detaching.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the helper module's crate-local intent"
)]

use std::collections::HashMap;

use sysdhardener_core::AddressFamily;

use crate::syscall::SyscallNumber;

use super::ObserveError;
use super::capture::TraceMode;

/// A captured syscall entry waiting for the matching exit stop.
#[derive(Debug, Clone)]
pub(super) struct PendingSyscall {
    pub(super) syscall: SyscallNumber,
    pub(super) family: Option<AddressFamily>,
    pub(super) socket_type: Option<u64>,
    pub(super) sockaddr_addr: Option<u64>,
    pub(super) fs_info: Option<(String, bool)>,
}

/// Per-tracee state: the pending syscall pair and the signal to
/// deliver on the next resume. Kept per process so fork-following
/// does not mix up the syscall stops of different processes.
pub(super) struct TraceeState {
    pub(super) pending: Option<PendingSyscall>,
    pub(super) options_set: bool,
    pub(super) in_syscall: bool,
    /// A signal to deliver on the next resume (set by the forward
    /// flag, delivered regardless of the stop type).
    pub(super) deliver_signal: libc::c_int,
}

impl TraceeState {
    pub(super) const fn new() -> Self {
        Self {
            pending: None,
            options_set: false,
            in_syscall: false,
            deliver_signal: 0,
        }
    }
}

/// Set the trace options on a stopped tracee: `TRACESYSGOOD` (syscall
/// stops carry `SIGTRAP|0x80`) plus fork/vfork/clone following so the
/// whole process tree is observed.
pub(super) fn setup_trace_options(pid: libc::pid_t) -> Result<(), ObserveError> {
    // SAFETY: PTRACE_SETOPTIONS on the stopped child; the options
    // make syscall stops carry SIGTRAP|0x80 and report fork events.
    let options: libc::c_long = i64::from(
        libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC,
    );
    let rc: libc::c_long = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            options as *mut libc::c_void,
        )
    };
    if rc < 0 {
        let errno: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(ObserveError::Wait(format!(
            "PTRACE_SETOPTIONS failed (errno {errno})"
        )));
    }
    Ok(())
}

/// Resume a stopped tracee to its next syscall stop, delivering the
/// tracee's pending forward signal (if any) or its own stop signal.
pub(super) fn resume(pid: libc::pid_t, state: &mut TraceeState, own_signal: libc::c_int) {
    let signal: libc::c_int = if state.deliver_signal != 0 {
        state.deliver_signal
    } else {
        own_signal
    };
    state.deliver_signal = 0;
    // SAFETY: PTRACE_SYSCALL resumes the stopped tracee; the signal
    // argument delivers the pending signal (0 = none).
    unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            signal as *mut libc::c_void,
        );
    }
}

/// Whether a ptrace event is a fork/vfork/clone (new tracee created).
pub(super) const fn is_fork_event(event: libc::c_int) -> bool {
    event == libc::PTRACE_EVENT_FORK
        || event == libc::PTRACE_EVENT_VFORK
        || event == libc::PTRACE_EVENT_CLONE
}

/// Handle a fork/vfork/clone event: read child pid, register it, resume parent.
pub(super) fn handle_fork_event(
    waited: libc::pid_t,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
) -> Result<(), ObserveError> {
    let mut new_pid: libc::c_ulong = 0;
    let pid_ptr: *mut libc::c_void = std::ptr::addr_of_mut!(new_pid).cast();
    let rc: libc::c_long = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG,
            waited,
            std::ptr::null_mut::<libc::c_void>(),
            pid_ptr,
        )
    };
    if rc < 0 {
        return Err(ObserveError::Wait("PTRACE_GETEVENTMSG failed".to_owned()));
    }
    let child: libc::pid_t = libc::pid_t::try_from(new_pid)
        .map_err(|_| ObserveError::Wait("new child pid overflow".to_owned()))?;
    tracees.entry(child).or_insert_with(TraceeState::new);
    if let Some(state) = tracees.get_mut(&waited) {
        resume(waited, state, 0);
    } else {
        unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                waited,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
        }
    }
    Ok(())
}

/// Register a newly forked child whose initial stop arrived before fork event.
pub(super) fn register_new_tracee(
    waited: libc::pid_t,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
) -> Result<(), ObserveError> {
    setup_trace_options(waited)?;
    let state = tracees.entry(waited).or_insert_with(TraceeState::new);
    state.options_set = true;
    unsafe {
        libc::ptrace(
            libc::PTRACE_SYSCALL,
            waited,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        );
    }
    Ok(())
}

/// Detach all currently tracked tracees with signal 0 so they continue executing.
pub(super) fn detach_all(tracees: &mut HashMap<libc::pid_t, TraceeState>) {
    for &pid in tracees.keys() {
        unsafe {
            let rc = libc::ptrace(
                libc::PTRACE_DETACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
            if rc < 0 {
                libc::ptrace(
                    libc::PTRACE_INTERRUPT,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
                let mut status = 0;
                for _ in 0..500 {
                    let w = libc::waitpid(pid, &raw mut status, libc::__WALL | libc::WNOHANG);
                    if w == pid || w < 0 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    pid,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
            }
        }
    }
    tracees.clear();
}

/// Kill and reap all remaining tracees when a spawned observation loop aborts.
pub(super) fn kill_all(tracees: &mut HashMap<libc::pid_t, TraceeState>) {
    for &pid in tracees.keys() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::ptrace(
                libc::PTRACE_CONT,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                libc::SIGKILL as *mut libc::c_void,
            );
            let mut status = 0;
            for _ in 0..500 {
                let w = libc::waitpid(pid, &raw mut status, libc::__WALL | libc::WNOHANG);
                if w == pid || w < 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    tracees.clear();
}

/// Clean up tracked tracees upon exiting the trace loop.
pub(super) fn clean_up_tracees(tracees: &mut HashMap<libc::pid_t, TraceeState>, mode: TraceMode) {
    if mode == TraceMode::Attach {
        detach_all(tracees);
    } else {
        kill_all(tracees);
    }
}

/// Wait for any tracee stop. Returns `Ok(None)` when all tracees are
/// gone (ECHILD), and `Ok(Some((pid, status)))` for one stop.
pub(super) fn wait_for_stop() -> Result<Option<(libc::pid_t, libc::c_int)>, ObserveError> {
    // SAFETY: waitpid(-1) waits for any tracee; the status is the
    // child's wait status, interpreted by the W* macros. __WALL waits
    // for all children including clone threads without SIGCHLD.
    let mut status: libc::c_int = 0;
    let status_ptr: *mut libc::c_int = std::ptr::addr_of_mut!(status);
    let waited: libc::pid_t = unsafe { libc::waitpid(-1, status_ptr, libc::__WALL) };
    if waited < 0 {
        let errno: i32 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ECHILD {
            return Ok(None);
        }
        if errno == libc::EINTR {
            return Ok(Some((0, 0)));
        }
        return Err(ObserveError::Wait("waitpid failed".to_owned()));
    }
    Ok(Some((waited, status)))
}

/// Handle tracee exit or signal termination.
///
/// Returns `Ok(true)` if all tracees have exited and the trace loop should finish,
/// or `Ok(false)` if other tracees remain running.
pub(super) fn handle_tracee_exit(
    waited: libc::pid_t,
    status: libc::c_int,
    main_pid: libc::pid_t,
    mode: TraceMode,
    tracees: &mut HashMap<libc::pid_t, TraceeState>,
) -> Result<bool, ObserveError> {
    let state = tracees.remove(&waited);
    if waited == main_pid && mode == TraceMode::Spawn && state.is_some_and(|s| !s.options_set) {
        let code: i32 = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        return Err(ObserveError::Spawn(format!(
            "target command failed to execute (exit status {code})"
        )));
    }
    Ok(tracees.is_empty())
}
