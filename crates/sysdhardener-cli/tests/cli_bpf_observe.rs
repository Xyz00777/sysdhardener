//! Error-path E2E tests for the feature-gated `bpf-observe` command.
//!
//! The happy path (real eBPF attach) requires root/`CAP_BPF` and a
//! BPF-enabled kernel, so it cannot run in this environment. The
//! **error paths** — unreadable object, garbage object, unopenable
//! cgroup — are fully testable without privileges and lock the
//! exit-code mapping (processing failure 4, usage 2).
//!
//! Compiled only when the `bpf-observe` feature is enabled (the
//! command does not exist in the default binary).
#![cfg(feature = "bpf-observe")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::path::PathBuf;
use std::process::Command;

use assert_cmd::cargo::cargo_bin;

fn binary_path() -> PathBuf {
    cargo_bin("sysdhardener")
}

fn unique_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sysd-bpf-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

#[test]
fn missing_object_is_exit_4_processing_failure() {
    let out = unique_dir("missing-obj");
    let status = Command::new(binary_path())
        .arg("bpf-observe")
        .arg("--object")
        .arg("/nonexistent/object.o")
        .arg("--cgroup")
        .arg("/sys/fs/cgroup")
        .arg("--output-dir")
        .arg(&out)
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(4));
}

#[test]
fn garbage_object_is_exit_4() {
    let dir = unique_dir("garbage-obj");
    let garbage = dir.join("garbage.o");
    std::fs::write(&garbage, b"this is not a valid eBPF object").expect("write garbage");
    let status = Command::new(binary_path())
        .arg("bpf-observe")
        .arg("--object")
        .arg(&garbage)
        .arg("--cgroup")
        .arg("/sys/fs/cgroup")
        .arg("--duration-ms")
        .arg("1")
        .arg("--output-dir")
        .arg(&dir)
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(4));
}

#[test]
fn unopenable_cgroup_is_exit_4() {
    let dir = unique_dir("no-cg");
    // A readable (dummy) object is needed so the failure comes from
    // the cgroup open, not the object read.
    let object = dir.join("object.o");
    std::fs::write(&object, b"dummy object bytes").expect("write object");
    let status = Command::new(binary_path())
        .arg("bpf-observe")
        .arg("--object")
        .arg(&object)
        .arg("--cgroup")
        .arg("/nonexistent-cgroup")
        .arg("--output-dir")
        .arg(&dir)
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(4));
}

#[test]
fn missing_required_arg_is_exit_2_usage() {
    let dir = unique_dir("usage");
    let status = Command::new(binary_path())
        .arg("bpf-observe")
        .arg("--object")
        .arg("/tmp/opaque.o")
        .arg("--output-dir")
        .arg(&dir)
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(2));
}
