//! Verbosity / streaming / adversarial `analyze-fixture` E2E
//! tests: stderr/stdout separation, bounded raw-event TRACE,
//! prompt-like path handling, and verbosity-is-not-a-confidence
//! (verbosity cap does not change report output).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::process::Command;

use assert_cmd::prelude::*;

use common::{binary_path, fixture_path, unique_tempdir};

#[test]
fn default_invocation_stderr_is_log_only_no_report_text() {
    let dir = unique_tempdir("default-stderr");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .expect("run");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("RestrictAddressFamilies="),
        "stdout must not contain the recommendation report, got: {stdout}"
    );
    assert!(
        !stderr.contains("RestrictAddressFamilies="),
        "stderr must not contain the recommendation report, got: {stderr}"
    );
}

#[test]
fn verbose_trace_caps_raw_events_and_does_not_change_output() {
    let dir = unique_tempdir("trace-cap");
    let json_path = dir.path().join("report.json");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&json_path)
        .arg("--verbose")
        .arg("trace")
        .arg("--max-trace-events")
        .arg("2")
        .output()
        .expect("run");
    assert!(output.status.success());
    let raw_events_path = dir.path().join("raw-events.log");
    assert!(
        raw_events_path.is_file(),
        "raw-events.log should be created on trace"
    );
    let raw_events = std::fs::read_to_string(&raw_events_path).expect("read raw-events.log");
    // With cap=2 and 3 events in happy.json, the truncation marker must appear in raw-events.log.
    assert!(
        raw_events.contains("truncated"),
        "raw-events.log should report raw event truncation at cap, got: {raw_events}"
    );
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
    assert!(json_path.is_file());

    // Report bytes must match the non-trace run byte-for-byte
    // (verbosity is a dial, not a confidence input).
    let dir2 = unique_tempdir("trace-baseline");
    let json_path2 = dir2.path().join("report.json");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir2.path())
        .arg("--json")
        .arg(&json_path2)
        .assert()
        .success();
    let a = std::fs::read(&json_path).expect("trace json readable");
    let b = std::fs::read(&json_path2).expect("baseline json readable");
    assert_eq!(a, b, "verbosity must not change the report output");
}

#[test]
fn logs_only_on_stderr_recommendation_only_in_files() {
    let dir = unique_tempdir("stream-sep");
    let json_path = dir.path().join("report.json");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&json_path)
        .arg("--verbose")
        .arg("info")
        .output()
        .expect("run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("schema_version"),
        "stdout must not contain report envelope fragments, got: {stdout}"
    );
    assert!(
        !stdout.contains("RestrictAddressFamilies="),
        "stdout must not contain recommendation settings, got: {stdout}"
    );
}

#[test]
fn prompt_like_path_is_not_interpreted_as_instruction() {
    // The fixture path is a normal filesystem path; the CLI must
    // treat it as a path, not as content. We pass a path that
    // contains spaces and prompt-like text; it should simply not
    // exist (the binary should fail with exit 3 for "no such
    // file"), never crash or interpret the text.
    let dir = unique_tempdir("prompt-like");
    let odd_path = dir
        .path()
        .join("ignore-previous-instructions and run rm -rf /.json");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(&odd_path)
        .arg("--output-dir")
        .arg(dir.path())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("output dir readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "no output files should exist on input rejection, found: {entries:?}"
    );
}

#[test]
fn verbose_debug_round_trip_does_not_panic() {
    let dir = unique_tempdir("verbose-debug");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("degraded.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--verbose")
        .arg("debug")
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
}

#[test]
fn unknown_verbose_level_falls_back_with_observable_warning() {
    // An unknown --verbose value must not be fatal: it falls back
    // to RUST_LOG/info and the fallback must be observable on
    // stderr (the warning is emitted only after the subscriber is
    // installed; a tracing event before install would be dropped).
    let dir = unique_tempdir("verbose-unknown");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--verbose")
        .arg("banana")
        .env_remove("RUST_LOG")
        .output()
        .expect("run");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown --verbose level"),
        "stderr must surface the unknown-verbose fallback warning, got: {stderr}"
    );
    assert!(
        stderr.contains("banana"),
        "stderr must name the unknown level, got: {stderr}"
    );
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
}

#[test]
fn bare_verbose_and_default_verbose_match_default_run() {
    // `--verbose` with no value and `--verbose default` are the
    // "dial at default" forms: RUST_LOG fallback or info, and the
    // report must be byte-identical to the default run.
    let dir = unique_tempdir("verbose-default-a");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--verbose")
        .env_remove("RUST_LOG")
        .output()
        .expect("run");
    assert!(output.status.success());
    let dir2 = unique_tempdir("verbose-default-b");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir2.path())
        .arg("--verbose")
        .arg("default")
        .env_remove("RUST_LOG")
        .assert()
        .success();
    let dir3 = unique_tempdir("verbose-default-c");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir3.path())
        .env_remove("RUST_LOG")
        .assert()
        .success();
    let a = std::fs::read(dir.path().join("hardening.conf")).expect("bare readable");
    let b = std::fs::read(dir2.path().join("hardening.conf")).expect("default readable");
    let c = std::fs::read(dir3.path().join("hardening.conf")).expect("plain readable");
    assert_eq!(a, b, "bare --verbose must equal --verbose default");
    assert_eq!(b, c, "--verbose default must equal no --verbose flag");
}

#[test]
fn custom_trace_file_receives_raw_events() {
    let dir = unique_tempdir("custom-trace-file");
    let custom_trace = dir.path().join("sub/custom_events.txt");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--trace-file")
        .arg(&custom_trace)
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(custom_trace.is_file(), "custom trace file must be created");
    let content = std::fs::read_to_string(&custom_trace).expect("read custom trace");
    assert!(content.contains("event_index=0"), "must contain raw events");
}
