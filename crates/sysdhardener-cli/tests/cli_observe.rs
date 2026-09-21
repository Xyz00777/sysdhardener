//! E2E test for `sysdhardener observe`: the live-observer mode of
//! the product. The binary spawns the syscall target under the
//! ptrace observer, captures its real syscalls, runs them through
//! the analysis engine, and writes the recommendation artifacts.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::process::Command;

use common::{binary_path, unique_tempdir};

/// Path to the syscall target binary. The bin lives in the observer
/// crate; the workspace target dir is shared, so the path is
/// `target/debug/syscall_target` relative to the workspace root.
fn target_binary() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("syscall_target");
    path
}

#[test]
fn observe_writes_findings_and_hardening_conf_exits_zero() {
    let dir = unique_tempdir("observe");
    let output = Command::new(binary_path())
        .arg("observe")
        .arg("--output-dir")
        .arg(dir.path())
        .arg(target_binary())
        .output()
        .expect("observe runs");
    assert!(
        output.status.success(),
        "observe must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings = dir.path().join("findings.txt");
    let hardening = dir.path().join("hardening.conf");
    assert!(findings.is_file(), "findings.txt must exist: {findings:?}");
    assert!(
        hardening.is_file(),
        "hardening.conf must exist: {hardening:?}"
    );
    let findings_text = std::fs::read_to_string(&findings).expect("findings.txt readable");
    assert!(
        findings_text.contains("RestrictAddressFamilies"),
        "findings.txt must mention the directive, got: {findings_text}"
    );
    assert!(
        findings_text.contains("SRC-12"),
        "findings.txt must carry the observer source ID, got: {findings_text}"
    );
    assert!(
        findings_text.contains("known_gaps: [getpeername, setpriority]"),
        "findings.txt must contain known_gaps even without --show-pids, got: {findings_text}"
    );
    let conf_text = std::fs::read_to_string(&hardening).expect("hardening.conf readable");
    assert!(
        conf_text.contains("RestrictAddressFamilies="),
        "hardening.conf must be a settings line, got: {conf_text}"
    );
    assert!(
        conf_text.contains("# WARNING:"),
        "hardening.conf must open with the concise warning, got: {conf_text}"
    );
}

#[test]
fn observe_compute_target_without_network_or_capabilities_succeeds_with_no_findings() {
    let dir = unique_tempdir("observe-compute");
    let output = Command::new(binary_path())
        .arg("observe")
        .arg("--output-dir")
        .arg(dir.path())
        .arg("true")
        .output()
        .expect("observe runs");
    assert!(
        output.status.success(),
        "observe must exit 0 on pure compute target; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings = dir.path().join("findings.txt");
    let hardening = dir.path().join("hardening.conf");
    assert!(findings.is_file());
    assert!(hardening.is_file());
    let findings_text = std::fs::read_to_string(&findings).expect("read findings");
    assert!(
        !findings_text.contains("RestrictAddressFamilies"),
        "findings.txt must not contain RestrictAddressFamilies for non-network target"
    );
    let conf_text = std::fs::read_to_string(&hardening).expect("read hardening");
    assert!(
        conf_text.contains("# WARNING:"),
        "hardening.conf must contain warning line, got: {conf_text}"
    );
    assert!(
        !conf_text.contains("RestrictAddressFamilies="),
        "hardening.conf must not recommend RestrictAddressFamilies for pure compute target"
    );
}

#[test]
fn observe_with_json_writes_report_envelope() {
    let dir = unique_tempdir("observe-json");
    let json_path = dir.path().join("report.json");
    let output = Command::new(binary_path())
        .arg("observe")
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&json_path)
        .arg(target_binary())
        .output()
        .expect("observe runs");
    assert!(
        output.status.success(),
        "observe must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&json_path).expect("json readable");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("report envelope must be valid JSON");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_i64),
        Some(1)
    );
    let findings = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .expect("findings array");
    assert!(
        !findings.is_empty(),
        "the live observation must produce at least one finding"
    );
}

#[test]
fn observe_forwards_sigterm_on_stop_and_writes_output() {
    // The systemd stop flow: `systemctl stop` sends SIGTERM to the
    // service (the observer). The observer must forward the signal
    // to the target process tree, wait for it to die, and write the
    // recommendation before exiting cleanly.
    let dir = unique_tempdir("observe-stop");
    let mut child = Command::new(binary_path())
        .arg("observe")
        .arg("--output-dir")
        .arg(dir.path())
        .arg(sleepy_target_binary())
        .spawn()
        .expect("observe must spawn");
    std::thread::sleep(std::time::Duration::from_millis(500));
    // SAFETY: kill the observer process with SIGTERM, as systemd
    // would on `systemctl stop`.
    let pid = libc::pid_t::try_from(child.id()).expect("observer pid fits in pid_t");
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    let status = child
        .wait()
        .expect("observer must exit after forwarding SIGTERM");
    assert!(
        status.success(),
        "observer must exit cleanly after SIGTERM, got {status:?}"
    );
    assert!(
        dir.path().join("hardening.conf").is_file(),
        "the recommendation must be written after the stop"
    );
    let conf_text = std::fs::read_to_string(dir.path().join("hardening.conf"))
        .expect("hardening.conf readable");
    assert!(
        conf_text.contains("RestrictAddressFamilies="),
        "hardening.conf must contain the recommendation, got: {conf_text}"
    );
}

#[test]
fn observe_passes_target_flags_without_intercepting_them() {
    let dir = unique_tempdir("observe-target-flags");
    // Pass flags that match sysdhardener's own option names (--output-dir, --verbose)
    // as arguments to the target command; trailing_var_arg ensures they are passed to the child.
    let output = Command::new(binary_path())
        .arg("observe")
        .arg("--output-dir")
        .arg(dir.path())
        .arg(target_binary())
        .arg("--output-dir")
        .arg("/ignored/child/path")
        .arg("--verbose")
        .arg("trace")
        .output()
        .expect("observe runs");
    assert!(
        output.status.success(),
        "observe must pass child flags without option collision; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
}

/// Path to the sleepy target binary: the long-running service that
/// must be terminated via signal forwarding.
fn sleepy_target_binary() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("sleepy_target");
    path
}
