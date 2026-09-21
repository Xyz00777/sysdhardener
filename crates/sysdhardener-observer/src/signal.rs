//! Signal and timer handling for the ptrace observer loop.
//!
//! Manages signal forwarding to tracees (SIGTERM/SIGINT from systemd stop),
//! observation window timers (SIGALRM), and RAII restoration of pre-existing
//! signal handlers so the host process is never permanently mutated.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the helper module's crate-local intent"
)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use crate::tracee::TraceeState;

/// The signal the observer must forward to the tracees, set by the
/// signal handler and consumed by the wait loop. `0` means "no
/// pending signal". Atomic so the handler (async-signal context) can
/// safely publish it.
pub(super) static FORWARD_SIGNAL: AtomicI32 = AtomicI32::new(0);

static ALARM_FIRED: AtomicBool = AtomicBool::new(false);
static TRACER_THREAD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Signal handler for `SIGTERM`/`SIGINT`/`SIGALRM`: publish the signal for the
/// wait loop to forward to every tracee or record alarm expiry.
extern "C" fn handle_forward_signal(sig: libc::c_int) {
    if sig == libc::SIGTERM || sig == libc::SIGINT {
        FORWARD_SIGNAL.store(sig, Ordering::SeqCst);
    } else if sig == libc::SIGALRM {
        ALARM_FIRED.store(true, Ordering::SeqCst);
    }
    let tracer = TRACER_THREAD.load(Ordering::SeqCst);
    let self_id = unsafe { libc::pthread_self() };
    if tracer != 0 && tracer != self_id {
        unsafe {
            libc::pthread_kill(tracer, sig);
        }
    }
}

/// RAII guard that restores previous signal actions on drop.
pub(super) struct SignalGuard {
    old_actions: [(libc::c_int, libc::sigaction); 3],
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        TRACER_THREAD.store(0, Ordering::SeqCst);
        unsafe {
            for (sig, action) in &self.old_actions {
                libc::sigaction(*sig, action, std::ptr::null_mut());
            }
        }
    }
}

/// Install the SIGTERM/SIGINT/SIGALRM handlers WITHOUT `SA_RESTART`, so a
/// blocked `waitpid()` returns `EINTR` when the signal arrives and
/// the loop can process the forward flag or timer.
///
/// Returns a [`SignalGuard`] that restores previous handlers when dropped.
#[allow(
    clippy::fn_to_numeric_cast_any,
    reason = "FFI: sigaction.sa_sigaction is sighandler_t (usize); handler cast required by C ABI"
)]
pub(super) fn install_forward_handlers() -> SignalGuard {
    FORWARD_SIGNAL.store(0, Ordering::SeqCst);
    TRACER_THREAD.store(unsafe { libc::pthread_self() }, Ordering::SeqCst);
    unsafe {
        let mut action: libc::sigaction = libc::sigaction {
            sa_sigaction: handle_forward_signal as *const () as libc::sighandler_t,
            ..std::mem::zeroed()
        };
        libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask));
        let action_ptr: *const libc::sigaction = std::ptr::addr_of!(action);
        let mut old_term: libc::sigaction = std::mem::zeroed();
        let mut old_int: libc::sigaction = std::mem::zeroed();
        let mut old_alrm: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGTERM, action_ptr, &raw mut old_term);
        libc::sigaction(libc::SIGINT, action_ptr, &raw mut old_int);
        libc::sigaction(libc::SIGALRM, action_ptr, &raw mut old_alrm);
        SignalGuard {
            old_actions: [
                (libc::SIGTERM, old_term),
                (libc::SIGINT, old_int),
                (libc::SIGALRM, old_alrm),
            ],
        }
    }
}

/// Arm a real-time interval timer to deliver SIGALRM after `duration_ms`.
pub(super) fn arm_timer(duration_ms: u64) {
    ALARM_FIRED.store(false, Ordering::SeqCst);
    TRACER_THREAD.store(unsafe { libc::pthread_self() }, Ordering::SeqCst);
    let mut it: libc::itimerval = unsafe { std::mem::zeroed() };
    let sec = duration_ms / 1000;
    let usec = (duration_ms % 1000) * 1000;
    it.it_value.tv_sec = i64::try_from(sec).unwrap_or(i64::MAX);
    it.it_value.tv_usec = i64::try_from(if duration_ms == 0 { 1 } else { usec }).unwrap_or(0);
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 50_000;
    unsafe {
        libc::setitimer(libc::ITIMER_REAL, &raw const it, std::ptr::null_mut());
    }
}

/// Disarm the real-time interval timer.
pub(super) fn disarm_timer() {
    ALARM_FIRED.store(false, Ordering::SeqCst);
    TRACER_THREAD.store(0, Ordering::SeqCst);
    let it: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe {
        libc::setitimer(libc::ITIMER_REAL, &raw const it, std::ptr::null_mut());
    }
}

/// Returns whether the observation window timer has expired.
pub(super) fn alarm_fired() -> bool {
    ALARM_FIRED.load(Ordering::SeqCst)
}

/// Forward a signal to every tracked tracee and mark its deliver flag.
pub(super) fn forward_signal(tracees: &mut HashMap<libc::pid_t, TraceeState>, signal: libc::c_int) {
    for &tpid in tracees.keys() {
        unsafe {
            libc::kill(tpid, signal);
        }
    }
    for state in tracees.values_mut() {
        state.deliver_signal = signal;
    }
}

/// Forward a pending stop signal (systemd stop) to every tracee.
pub(super) fn handle_forward_flag(tracees: &mut HashMap<libc::pid_t, TraceeState>) -> bool {
    let forward: libc::c_int = FORWARD_SIGNAL.swap(0, Ordering::SeqCst);
    if forward == 0 {
        return false;
    }
    forward_signal(tracees, forward);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_signal_does_not_fire_alarm_on_sigint() {
        let _guard = install_forward_handlers();
        FORWARD_SIGNAL.store(0, Ordering::SeqCst);
        ALARM_FIRED.store(false, Ordering::SeqCst);

        let handle = std::thread::spawn(|| {
            handle_forward_signal(libc::SIGINT);
        });
        handle.join().unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(FORWARD_SIGNAL.load(Ordering::SeqCst), libc::SIGINT);
        assert!(!alarm_fired(), "SIGINT must not set ALARM_FIRED to true");
    }
}
