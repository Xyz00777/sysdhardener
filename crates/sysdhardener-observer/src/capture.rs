//! Ptrace-based syscall capture loop.
//!
//! This is the **only** module in the workspace that calls raw libc.
//! The unsafe is confined here: `ptrace`, `waitpid`, and `PEEKDATA`
//! are inherently unsafe FFI. Every unsafe block has a safety comment
//! stating the invariant it relies on.

// `pub(super)` items inside a private module trip
// `redundant_pub_crate`; the explicit marker is intentional for the
// sibling-module contract (`attach.rs` reuses the trace loop).
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the sibling-module contract"
)]
//!
//! # Capture model
//!
//! The observer forks the target under `PTRACE_TRACEME`, then drives
//! it with `PTRACE_SYSCALL` (with `PTRACE_O_TRACESYSGOOD` so syscall
//! stops are distinguishable from signal stops). At each syscall
//! entry stop the register file is read (syscall number + arguments);
//! at the matching exit stop the return value is read. The pair is
//! decoded into an [`ObservedEvent`] and collected.
//!
//! # Whole-process-tree observation
//!
//! The observer follows every fork/vfork/clone the target performs
//! (`PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE`):
//! each new child is added to the tracee set with its own per-process
//! state, so the syscalls of the whole process tree — the service and
//! every subprocess it spawns — are captured from start to finish.
//!
//! # Signal forwarding
//!
//! The observer installs handlers for `SIGTERM` and `SIGINT` (the
//! signals systemd sends on `systemctl stop`). The handler only sets
//! an atomic flag; the wait loop notices the flag and resumes every
//! tracee with the signal, so the target process tree actually
//! terminates and the observer can write its output. The observer
//! never injects code and never modifies the target's memory.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::sync::atomic::Ordering;

use sysdhardener_core::ObservedEvent;

use crate::ptrace_abi::{capture_entry, handle_exit, read_regs};
use crate::signal::{
    FORWARD_SIGNAL, alarm_fired, arm_timer, disarm_timer, handle_forward_flag,
    install_forward_handlers,
};
use crate::tracee::{
    TraceeState, clean_up_tracees, handle_fork_event, handle_tracee_exit, is_fork_event,
    register_new_tracee, resume, setup_trace_options, wait_for_stop,
};

/// The tracing mode: spawn a child or attach to an existing process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TraceMode {
    Spawn,
    Attach,
}

/// Typed failure of the capture loop.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObserveError {
    /// The target could not be spawned.
    #[error("target could not be spawned: {0}")]
    Spawn(String),
    /// The ptrace wait loop hit an unexpected wait status.
    #[error("unexpected wait status: {0}")]
    Wait(String),
    /// Reading the register file failed.
    #[error("register read failed: {0}")]
    Registers(String),
    /// Reading the target's memory (sockaddr) failed.
    #[error("target memory read failed: {0}")]
    Memory(String),
}

/// The ptrace-based observer. A unit value; each [`observe`] call
/// spawns and traces a fresh target.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtraceObserver;

impl PtraceObserver {
    /// Spawn `command` under ptrace, capture the address-family
    /// syscalls of the whole process tree, and return the typed event
    /// stream.
    ///
    /// # Errors
    /// Returns [`ObserveError`] when the target cannot be spawned or
    /// the wait loop hits an unexpected state.
    pub fn observe(&self, command: &mut Command) -> Result<Vec<ObservedEvent>, ObserveError> {
        observe_command(command)
    }
}

/// Serializes concurrent `observe_command` calls within one process.
/// The wait loop uses `waitpid(-1)`, which would otherwise reap
/// another thread's traced children, and the signal handlers are
/// process-global. The observer is a process-level operation; the
/// lock keeps two threads (e.g. tests in parallel) from interfering.
pub(super) static OBSERVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Spawn `command` under ptrace and capture the address-family
/// syscalls of the whole process tree as typed events.
///
/// # Errors
/// Returns [`ObserveError`] when the target cannot be spawned or the
/// wait loop hits an unexpected state.
pub fn observe_command(command: &mut Command) -> Result<Vec<ObservedEvent>, ObserveError> {
    let _guard = OBSERVE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _sig_guard = install_forward_handlers();
    let pid = spawn_tracee(command)?;
    run_trace_loop(&[pid], TraceMode::Spawn, None)
}

fn build_child_env(command: &Command) -> Result<Option<Vec<CString>>, ObserveError> {
    if command.get_envs().next().is_none() {
        return Ok(None);
    }
    let mut map: HashMap<std::ffi::OsString, std::ffi::OsString> = std::env::vars_os().collect();
    for (k, v) in command.get_envs() {
        if let Some(v) = v {
            map.insert(k.to_os_string(), v.to_os_string());
        } else {
            map.remove(k);
        }
    }
    let mut envs = Vec::new();
    for (k, v) in map {
        let mut line = k;
        line.push("=");
        line.push(v);
        let cstr = CString::new(line.as_os_str().as_bytes())
            .map_err(|_| ObserveError::Spawn("environment variable contains NUL".to_owned()))?;
        envs.push(cstr);
    }
    Ok(Some(envs))
}

/// Fork the tracee under `PTRACE_TRACEME` and exec the target.
fn spawn_tracee(command: &Command) -> Result<libc::pid_t, ObserveError> {
    let program: CString = CString::new(command.get_program().as_bytes())
        .map_err(|_| ObserveError::Spawn("program path contains NUL".to_owned()))?;
    let arg_strings: Vec<CString> = command
        .get_args()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| ObserveError::Spawn("argument contains NUL".to_owned()))?;
    let cwd: Option<CString> = command
        .get_current_dir()
        .map(|p| CString::new(p.as_os_str().as_bytes()))
        .transpose()
        .map_err(|_| ObserveError::Spawn("working directory contains NUL".to_owned()))?;
    let env_strings = build_child_env(command)?;
    let envp: Option<Vec<*const libc::c_char>> = env_strings.as_ref().map(|envs| {
        let mut ptrs: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        ptrs
    });
    let mut argv: Vec<*const libc::c_char> = arg_strings.iter().map(|a| a.as_ptr()).collect();
    argv.insert(0, program.as_ptr());
    argv.push(std::ptr::null());

    // SAFETY: the child calls PTRACE_TRACEME before exec, so the
    // parent's ptrace calls target a child it owns. The child then
    // execs the target program; on exec failure we call _exit(127)
    // so the child never returns into the caller's stack frame.
    let pid: libc::pid_t = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ObserveError::Spawn("fork failed".to_owned()));
    }
    if pid == 0 {
        // Child: change working directory if configured, request tracing, then exec the target.
        // SAFETY: PTRACE_TRACEME on self is the standard pre-exec
        // trace request; the parent is the tracer by construction.
        unsafe {
            if let Some(ref dir) = cwd {
                if libc::chdir(dir.as_ptr()) != 0 {
                    libc::_exit(127);
                }
            }
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                libc::_exit(127);
            }
            if let Some(ref envp_ptrs) = envp {
                libc::execvpe(program.as_ptr(), argv.as_ptr(), envp_ptrs.as_ptr());
            } else {
                libc::execvp(program.as_ptr(), argv.as_ptr());
            }
            libc::_exit(127);
        }
    }
    Ok(pid)
}

/// The main wait loop: drive every tracee until the process tree is
/// gone or the observation window elapses.
struct TraceLoopGuard<'a> {
    tracees: &'a mut HashMap<libc::pid_t, TraceeState>,
    mode: TraceMode,
}

impl Drop for TraceLoopGuard<'_> {
    fn drop(&mut self) {
        disarm_timer();
        clean_up_tracees(self.tracees, self.mode);
    }
}

fn init_deadline(ms: Option<u64>) -> Result<Option<std::time::Instant>, ObserveError> {
    ms.map(|d| {
        arm_timer(d);
        std::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(d))
            .ok_or_else(|| ObserveError::Wait("duration overflow".to_owned()))
    })
    .transpose()
}

pub(super) fn run_trace_loop(
    initial_pids: &[libc::pid_t],
    mode: TraceMode,
    duration_ms: Option<u64>,
) -> Result<Vec<ObservedEvent>, ObserveError> {
    let deadline = init_deadline(duration_ms)?;
    let main_pid = initial_pids.first().copied().unwrap_or(0);
    // Parent: drive the trace loop over the whole process tree.
    let mut events: Vec<ObservedEvent> = Vec::new();
    let mut tracees: HashMap<libc::pid_t, TraceeState> = initial_pids
        .iter()
        .map(|&p| (p, TraceeState::new()))
        .collect();
    let guard = TraceLoopGuard {
        tracees: &mut tracees,
        mode,
    };

    loop {
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl || alarm_fired() {
                break;
            }
        }
        if mode == TraceMode::Attach && FORWARD_SIGNAL.load(Ordering::SeqCst) != 0 {
            FORWARD_SIGNAL.store(0, Ordering::SeqCst);
            break;
        }
        if mode == TraceMode::Spawn && handle_forward_flag(guard.tracees) {
            continue;
        }

        let Some((waited, status)) = wait_for_stop()? else {
            // All tracees are gone; the observation is complete.
            break;
        };
        if waited == 0 {
            // EINTR: loop to re-check the forward flag or deadline.
            continue;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            match handle_tracee_exit(waited, status, main_pid, mode, guard.tracees) {
                Ok(true) => break,
                Ok(false) => continue,
                Err(err) => return Err(err),
            }
        }
        if !libc::WIFSTOPPED(status) {
            return Err(ObserveError::Wait(format!("unexpected status {status}")));
        }

        let stop_sig: libc::c_int = libc::WSTOPSIG(status);
        let event: libc::c_int = (status >> 16) & 0xffff;

        // A fork/vfork/clone event: the new child is created stopped.
        // Read its pid, resume the parent, and let the main wait loop
        // pick up the child's initial stop (the unknown-pid branch
        // below sets its options when it arrives).
        if is_fork_event(event) {
            handle_fork_event(waited, guard.tracees)?;
            continue;
        }

        // A stop from an unknown pid: a newly forked child whose
        // initial stop arrived before (or without) the fork event.
        // Register it and set its options.
        if !guard.tracees.contains_key(&waited) {
            register_new_tracee(waited, guard.tracees)?;
            continue;
        }

        let state: &mut TraceeState = guard
            .tracees
            .get_mut(&waited)
            .ok_or_else(|| ObserveError::Wait(format!("untracked tracee {waited}")))?;

        if !state.options_set {
            // The first stop of a tracee (the exec stop for the
            // initial child, the creation stop for fork children).
            // Set the trace options so syscall stops carry
            // SIGTRAP|0x80 and fork events are reported.
            setup_trace_options(waited)?;
            state.options_set = true;
            // SAFETY: resume the tracee to its first syscall stop.
            unsafe {
                libc::ptrace(
                    libc::PTRACE_SYSCALL,
                    waited,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                );
            }
            continue;
        }

        if event == libc::PTRACE_EVENT_EXEC {
            // PTRACE_EVENT_EXEC occurs during execve before the syscall returns;
            // mark in_syscall = true so the upcoming execve syscall-exit stop is
            // recognized as an exit stop and does not invert subsequent syscalls.
            state.in_syscall = true;
            state.pending = None;
            resume(waited, state, 0);
            continue;
        }

        if event != 0 {
            // Ptrace event stops (e.g. PTRACE_EVENT_STOP, VFORK_DONE) are not
            // signal-delivery stops; never deliver stop_sig (SIGTRAP) as a signal.
            resume(waited, state, 0);
            continue;
        }

        if stop_sig == (libc::SIGTRAP | 0x80) {
            // Syscall stop.
            let regs = read_regs(waited)?;
            let is_entry: bool = !state.in_syscall;
            if is_entry {
                state.in_syscall = true;
                state.pending = capture_entry(waited, &regs);
            } else {
                state.in_syscall = false;
                state.pending = handle_exit(waited, &regs, state.pending.take(), &mut events);
            }
            resume(waited, state, 0);
        } else {
            // A signal stop: the tracee's own signal is pending;
            // deliver it (or the forward signal, if one is set).
            resume(waited, state, stop_sig);
        }
    }

    Ok(events)
}
