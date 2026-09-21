//! Happy-path `analyze-fixture` E2E tests: --help, --version,
//! default invocation, JSON opt-in, and the selectable
//! single-sink combinations. Every test pins one observable
//! behavior through the public CLI surface only.

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
fn help_exits_zero_lists_analyze_fixture_subcommand() {
    let output = Command::new(binary_path())
        .arg("--help")
        .output()
        .expect("help runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let predicate = predicate::str::contains("analyze-fixture");
    assert!(
        predicate.eval(&stdout),
        "--help should mention analyze-fixture, got: {stdout}"
    );
}

#[test]
fn help_does_not_write_output_files() {
    let dir = unique_tempdir("help-no-files");
    let output = Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--help")
        .output()
        .expect("help runs");
    assert!(output.status.success());
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("output dir readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        entries.is_empty(),
        "--help must not produce output files; found: {entries:?}"
    );
}

#[test]
fn version_exits_zero_prints_semver() {
    let output = Command::new(binary_path())
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
        "version should be name + semver, got: {trimmed:?}"
    );
}

#[test]
fn default_invocation_writes_findings_and_hardening_conf_exits_zero() {
    let dir = unique_tempdir("default");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .assert()
        .success();
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
fn missing_output_dir_is_created_automatically() {
    let dir = unique_tempdir("auto-mkdir");
    let nested = dir.path().join("a").join("b").join("c");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(&nested)
        .assert()
        .success();
    assert!(
        nested.join("findings.txt").is_file(),
        "output dir must be created and findings written: {nested:?}"
    );
    assert!(
        nested.join("hardening.conf").is_file(),
        "output dir must be created and hardening.conf written"
    );
}

#[test]
fn json_opt_in_writes_report_envelope_v1_with_schema_version() {
    let dir = unique_tempdir("json");
    let json_path = dir.path().join("report.json");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--json")
        .arg(&json_path)
        .assert()
        .success();
    let text = std::fs::read_to_string(&json_path).expect("json readable");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("report envelope must be valid JSON");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "report envelope schema_version must be 1, got: {value}"
    );
    let findings = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .expect("findings must be an array");
    assert!(!findings.is_empty(), "findings must not be empty");
    let first = findings
        .first()
        .expect("findings is non-empty (asserted above)");
    let directive = first.get("directive").and_then(serde_json::Value::as_str);
    assert_eq!(directive, Some("RestrictAddressFamilies"));
    assert!(dir.path().join("findings.txt").is_file());
    assert!(dir.path().join("hardening.conf").is_file());
}

#[test]
fn no_detailed_writes_only_hardening_conf() {
    let dir = unique_tempdir("no-detailed");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--no-detailed")
        .assert()
        .success();
    assert!(
        !dir.path().join("findings.txt").exists(),
        "findings.txt must NOT exist when --no-detailed is set"
    );
    assert!(
        dir.path().join("hardening.conf").is_file(),
        "hardening.conf must still exist"
    );
}

#[test]
fn no_concise_writes_only_findings_txt() {
    let dir = unique_tempdir("no-concise");
    Command::new(binary_path())
        .arg("analyze-fixture")
        .arg(fixture_path("happy.json"))
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--no-concise")
        .assert()
        .success();
    assert!(
        dir.path().join("findings.txt").is_file(),
        "findings.txt must still exist"
    );
    assert!(
        !dir.path().join("hardening.conf").exists(),
        "hardening.conf must NOT exist when --no-concise is set"
    );
}

#[test]
fn json_only_with_both_no_flags_writes_only_report_json() {
    let dir = unique_tempdir("json-only");
    let json_path = dir.path().join("report.json");
    Command::new(binary_path())
        .args(["analyze-fixture", "--no-detailed", "--no-concise", "--json"])
        .arg(&json_path)
        .arg("--output-dir")
        .arg(dir.path())
        .arg(fixture_path("happy.json"))
        .assert()
        .success();
    assert!(
        !dir.path().join("findings.txt").exists(),
        "findings.txt must NOT exist when --no-detailed is set"
    );
    assert!(
        !dir.path().join("hardening.conf").exists(),
        "hardening.conf must NOT exist when --no-concise is set"
    );
    assert!(json_path.is_file(), "report.json must exist");
}

#[test]
fn analyze_fixture_with_empty_events_succeeds_with_no_findings() {
    let dir = unique_tempdir("empty-fixture");
    Command::new(binary_path())
        .args(["analyze-fixture", "--output-dir"])
        .arg(dir.path())
        .arg(fixture_path("empty.json"))
        .assert()
        .success();
    let findings = dir.path().join("findings.txt");
    let hardening = dir.path().join("hardening.conf");
    assert!(findings.is_file());
    assert!(hardening.is_file());
    let findings_text = std::fs::read_to_string(&findings).expect("read findings");
    assert!(
        findings_text.contains("(no findings)"),
        "findings.txt must report (no findings), got: {findings_text}"
    );
    let conf_text = std::fs::read_to_string(&hardening).expect("read hardening");
    assert!(
        conf_text.contains("# WARNING:"),
        "hardening.conf must contain warning line, got: {conf_text}"
    );
    assert!(
        !conf_text.contains("RestrictAddressFamilies="),
        "hardening.conf must not recommend RestrictAddressFamilies for empty events"
    );
}
