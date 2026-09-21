//! Safety and robustness tests for the ptrace observer.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions"
)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use sysdhardener_observer::{ObserveError, observe_command};

#[test]
fn nul_byte_in_program_path_fails_safely_without_leaking_child() {
    let invalid_prog = OsStr::from_bytes(b"/bin/tr\0ue");
    let mut cmd = Command::new(invalid_prog);
    let result = observe_command(&mut cmd);
    assert!(
        matches!(result, Err(ObserveError::Spawn(_))),
        "observer must return a spawn error for invalid program; got {result:?}"
    );
}

#[test]
fn nonexistent_binary_fails_with_spawn_error() {
    let mut cmd = Command::new("/nonexistent/binary/path/xyz_123");
    let result = observe_command(&mut cmd);
    assert!(
        matches!(result, Err(ObserveError::Spawn(_))),
        "observer must return a spawn error for nonexistent binary; got {result:?}"
    );
}

#[test]
fn nul_byte_in_current_dir_fails_safely() {
    let invalid_dir = OsStr::from_bytes(b"/tm\0p");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syscall_target"));
    cmd.current_dir(invalid_dir);
    let result = observe_command(&mut cmd);
    assert!(
        matches!(result, Err(ObserveError::Spawn(_))),
        "observer must return a spawn error for invalid current_dir; got {result:?}"
    );
}

#[test]
fn valid_current_dir_is_respected() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syscall_target"));
    cmd.current_dir("/");
    let result = observe_command(&mut cmd);
    assert!(
        result.is_ok(),
        "observer must succeed with current_dir; got {result:?}"
    );
}

#[test]
fn nul_byte_in_env_fails_safely() {
    let invalid_val = OsStr::from_bytes(b"val\0ue");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syscall_target"));
    cmd.env("TEST_VAR", invalid_val);
    let result = observe_command(&mut cmd);
    assert!(
        matches!(result, Err(ObserveError::Spawn(_))),
        "observer must return a spawn error for invalid env; got {result:?}"
    );
}

#[test]
fn custom_env_vars_are_passed_to_child() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c");
    cmd.arg("if [ \"$TEST_SYSD_VAR\" != \"hello_123\" ]; then exit 42; fi");
    cmd.env("TEST_SYSD_VAR", "hello_123");
    let result = observe_command(&mut cmd);
    assert!(
        result.is_ok(),
        "command must succeed with custom env; got {result:?}"
    );
}
