//! Error-path `analyze-fixture` E2E tests: clap usage errors
//! (exit 2), invalid fixture / input boundary failures (exit 3),
//! processing failures (exit 4), and partial sink failures
//! (exit 5). Each test pins one observable behavior through the
//! public CLI surface only.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use common::{binary_path, fixture_path, unique_tempdir};

#[test]
fn no_sink_selected_is_rejected_with_exit_2() {
    let dir = unique_tempdir("no-sink");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--no-detailed")
        .arg("--no-concise")
        .assert()
        .failure()
        .code(2)
        .stderr(
            predicate::str::contains("at least one file sink")
                .or(predicate::str::contains("detailed, concise, json"))
                .or(predicate::str::contains("usage")),
        );
    assert!(!dir.path().join("findings.txt").exists());
    assert!(!dir.path().join("hardening.conf").exists());
}

#[test]
fn missing_fixture_argument_is_rejected_with_exit_2() {
    let dir = unique_tempdir("missing-arg");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg("--output-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .code(2);
}

#[test]
fn unknown_flag_is_rejected_with_exit_2() {
    let dir = unique_tempdir("bad-flag");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--not-a-real-flag")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn malformed_fixture_exits_three_with_no_files() {
    let dir = unique_tempdir("malformed");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("malformed.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(dir.path().join("report.json"))
        .assert()
        .failure()
        .code(3);
    assert!(!dir.path().join("findings.txt").exists());
    assert!(!dir.path().join("hardening.conf").exists());
    assert!(!dir.path().join("report.json").exists());
}

#[test]
fn unknown_schema_fixture_exits_three() {
    let dir = unique_tempdir("unknown-schema");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("unknown-schema.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .code(3);
    assert!(!dir.path().join("findings.txt").exists());
    assert!(!dir.path().join("hardening.conf").exists());
}

#[test]
fn missing_fixture_file_exits_three() {
    let dir = unique_tempdir("missing-fixture");
    let nonexistent = dir.path().join("nonexistent.json");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(&nonexistent)
        .arg("--output-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .code(3);
}

#[test]
fn processing_failure_exits_four_with_no_output_files() {
    // A fixture where every event has outcome != success produces
    // an empty `recommended_families` set; the concise projection
    // rejects this with `Error::UnlinkedConciseSetting`, which the
    // analysis seam maps to `ProcessingFailed` (exit 4). The
    // fixture is built inline so this test owns the
    // processing-failure input surface.
    let dir = unique_tempdir("processing-failure");
    let fx = dir.path().join("proc-fail.json");
    std::fs::write(
        &fx,
        r#"{
            "schema_version": 1,
            "fixture_id": "no-successful-outcome",
            "first_timestamp_unix_ms": 1700000000000,
            "last_timestamp_unix_ms": 1700000002000,
            "coverage": "complete",
            "seen_events": 2,
            "dropped_events": 0,
            "events": [
                {
                    "source_id": "SRC-01",
                    "event_id": "evt-001",
                    "timestamp_unix_ms": 1700000000000,
                    "address_family": "unix",
                    "outcome": "error",
                    "args": "connect /var/run/sock"
                },
                {
                    "source_id": "SRC-01",
                    "event_id": "evt-002",
                    "timestamp_unix_ms": 1700000002000,
                    "address_family": "inet",
                    "outcome": "error",
                    "args": "bind 0.0.0.0:80"
                }
            ]
        }"#,
    )
    .expect("fixture should be writable");

    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(&fx)
        .arg("--output-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .code(4);
    assert!(!dir.path().join("findings.txt").exists());
    assert!(!dir.path().join("hardening.conf").exists());
}

#[test]
fn partial_sink_failure_preserves_other_outputs_and_exits_five() {
    let dir = unique_tempdir("partial-sink");
    // Arrange the *detailed* output path to be an existing
    // directory so `File::create` returns `IsADirectory` and the
    // detailed sink fails; the concise + JSON sinks should still
    // succeed and exit should be 5.
    let blocked = dir.path().join("findings.txt");
    std::fs::create_dir(&blocked).expect("blocked dir should be creatable");
    let json_path = dir.path().join("report.json");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&json_path)
        .output()
        .expect("run");
    assert_eq!(
        output.status.code(),
        Some(5),
        "expected exit 5 on partial sink failure, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        dir.path().join("hardening.conf").is_file(),
        "concise output (hardening.conf) must be preserved on partial failure"
    );
    assert!(
        json_path.is_file(),
        "json output (report.json) must be preserved on partial failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("detailed") || stderr.contains("findings.txt"),
        "stderr must name the failed sink, got: {stderr}"
    );
}

#[test]
fn output_dir_inside_a_file_exits_four_with_no_sinks_attempted() {
    // If --output-dir points to an existing regular file, no sink
    // can possibly write. The binary creates the directory once
    // before driving any sink; the failure is a processing-phase
    // failure (exit 4), not a per-sink partial failure (exit 5),
    // and no sink is attempted.
    let dir = unique_tempdir("output-is-file");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").expect("blocker writable");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(&blocker)
        .output()
        .expect("run");
    assert_eq!(
        output.status.code(),
        Some(4),
        "output-dir that is a file should produce processing-failed exit 4, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("processing failed") && stderr.contains("output directory"),
        "stderr must name the output-directory failure, got: {stderr}"
    );
}

#[test]
fn analyze_fixture_accepts_options_before_positional_fixture() {
    let dir = unique_tempdir("options-first");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg("--output-dir")
        .arg(dir.path())
        .arg(fixture_path("happy.json"))
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "analyze-fixture must accept options before the positional argument; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
}

#[test]
fn analyze_fixture_rejects_duplicate_output_dir_flag() {
    let dir = unique_tempdir("dup-flag");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg("--output-dir")
        .arg(dir.path())
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg("/duplicate/path")
        .output()
        .expect("run");
    assert_eq!(
        output.status.code(),
        Some(2),
        "duplicate --output-dir must be rejected as clap usage error"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot be used multiple times"));
}
