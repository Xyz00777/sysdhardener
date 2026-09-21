//! Verification of RAII signal handler restoration for observer and attach.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions"
)]

use std::process::Command;
use sysdhardener_observer::{observe_command, observe_pid};

const extern "C" fn dummy_sigalrm_handler(_sig: libc::c_int) {}

#[allow(
    clippy::fn_to_numeric_cast_any,
    reason = "FFI: sigaction.sa_sigaction is sighandler_t; cast required by C ABI"
)]
#[test]
fn observer_restores_prior_signal_handlers_on_exit() {
    unsafe {
        let mut custom_action: libc::sigaction = libc::sigaction {
            sa_sigaction: dummy_sigalrm_handler as *const () as libc::sighandler_t,
            ..std::mem::zeroed()
        };
        libc::sigemptyset(std::ptr::addr_of_mut!(custom_action.sa_mask));
        let mut original_alrm: libc::sigaction = std::mem::zeroed();
        libc::sigaction(
            libc::SIGALRM,
            &raw const custom_action,
            &raw mut original_alrm,
        );

        // 1. observe_command restores prior signal action on completion.
        let target_path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_syscall_target"));
        let mut cmd = Command::new(target_path);
        let result = observe_command(&mut cmd);
        assert!(result.is_ok());

        let mut restored_alrm: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGALRM, std::ptr::null(), &raw mut restored_alrm);
        assert_eq!(
            restored_alrm.sa_sigaction, dummy_sigalrm_handler as *const () as libc::sighandler_t,
            "observe_command must restore prior sigaction on completion"
        );

        // 2. observe_pid restores prior signal action on completion/failure.
        let _ = observe_pid(0);
        let mut restored_alrm2: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGALRM, std::ptr::null(), &raw mut restored_alrm2);
        assert_eq!(
            restored_alrm2.sa_sigaction, dummy_sigalrm_handler as *const () as libc::sighandler_t,
            "observe_pid must restore prior sigaction on failure"
        );

        // Clean up: restore what original_alrm was before this test ran.
        libc::sigaction(
            libc::SIGALRM,
            &raw const original_alrm,
            std::ptr::null_mut(),
        );
    }
}
