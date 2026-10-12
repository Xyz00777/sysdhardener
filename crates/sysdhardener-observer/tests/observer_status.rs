//! Characterization tests for target process status reporting.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert process-boundary behavior"
)]

use std::process::Command;

use sysdhardener_observer::{TargetStatus, observe_command, observe_command_with_status};

#[test]
fn main_exit_code_is_reported_without_changing_legacy_events_api() {
    let mut command = Command::new("sh");
    command.args(["-c", "exit 23"]);

    let result = observe_command_with_status(&mut command).expect("observation completes");

    assert_eq!(result.target_status(), TargetStatus::Exited(23));
    let _events = result.events();

    let mut legacy = Command::new("sh");
    legacy.args(["-c", "exit 0"]);
    let _legacy_events = observe_command(&mut legacy).expect("legacy observation completes");
}

#[test]
fn signal_status_identifies_the_main_process_signal() {
    let mut command = Command::new("sh");
    command.args(["-c", "kill -TERM $$"]);

    let result = observe_command_with_status(&mut command).expect("observation completes");

    assert_eq!(
        result.target_status(),
        TargetStatus::Signaled(libc::SIGTERM)
    );
}

#[test]
fn successful_target_reports_zero_exit_code() {
    let mut command = Command::new("true");

    let result = observe_command_with_status(&mut command).expect("observation completes");

    assert_eq!(result.target_status(), TargetStatus::Exited(0));
}

#[test]
fn child_exit_does_not_replace_main_process_status() {
    let mut command = Command::new("sh");
    command.args(["-c", "(sleep 0.1; exit 7) & exit 23"]);

    let result = observe_command_with_status(&mut command).expect("observation completes");

    assert_eq!(result.target_status(), TargetStatus::Exited(23));
}

#[test]
fn nonexistent_command_remains_a_spawn_error() {
    let mut command = Command::new("/definitely/not/a/sysdhardener-command");

    let error = observe_command_with_status(&mut command).expect_err("exec must fail");

    assert!(matches!(
        error,
        sysdhardener_observer::ObserveError::Spawn(_)
    ));
}
