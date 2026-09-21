//! CLI smoke tests.
//!
//! Verifies the baseline binary surface: `--help` exits 0 and prints
//! the binary name, and `--version` exits 0 and prints a semver-looking string.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_exit_zero_and_prints_name() {
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sysdhardener"));
}

#[test]
fn version_exit_zero_and_prints_semver() {
    let output = Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .arg("--version")
        .output()
        .expect("version runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    assert!(
        trimmed.contains("sysdhardener") && trimmed.contains('.'),
        "version output should be name + semver, got: {trimmed:?}"
    );
}

#[test]
fn attach_help_exposes_show_pids_flag() {
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args(["attach", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--show-pids"));
}

#[test]
fn attach_help_exposes_duration_ms_flag() {
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args(["attach", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--duration-ms"));
}

#[test]
fn attach_zero_pid_is_rejected_as_usage_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args([
            "attach",
            "0",
            "--output-dir",
            temp.path().to_str().expect("path"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "target pid must be positive and non-zero",
        ));
}

#[test]
fn attach_out_of_range_pid_is_rejected_as_usage_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args([
            "attach",
            "3000000000",
            "--output-dir",
            temp.path().to_str().expect("path"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "target pid must be positive and non-zero",
        ));
}

#[test]
fn attach_accepts_options_before_positional_pid() {
    let temp = tempfile::tempdir().expect("tempdir");
    // Verifies that placing options before the positional PID works identically
    // and produces the expected domain validation error rather than a clap syntax error.
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args([
            "attach",
            "--output-dir",
            temp.path().to_str().expect("path"),
            "0",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "target pid must be positive and non-zero",
        ));
}

#[test]
fn attach_rejects_duplicate_output_dir_flag() {
    let temp = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .args([
            "attach",
            "--output-dir",
            temp.path().to_str().expect("path"),
            "12345",
            "--output-dir",
            "/other/path",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used multiple times"));
}

#[test]
fn unparseable_rust_log_falls_back_and_warns() {
    let temp = tempfile::tempdir().expect("tempdir");
    Command::cargo_bin("sysdhardener")
        .expect("binary should build for tests")
        .env("RUST_LOG", "=bad_level")
        .args([
            "attach",
            "0",
            "--output-dir",
            temp.path().to_str().expect("path"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "RUST_LOG is set but empty or unparseable; falling back to info",
        ));
}
