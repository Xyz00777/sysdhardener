//! Happy-path integration tests for the three independent `OutputSink`
//! file adapters.
//!
//! Locked invariants:
//! - each sink writes to a caller-selected path under a unique
//!   unique process-private tempdir and reports its own typed success;
//! - `DetailedFileSink` produces a detailed findings list whose
//!   per-entry fields are machine-parsable;
//! - `ConciseFileSink` produces a concise view that begins with
//!   exactly one `CONCISE_WARNING` line followed only by setting
//!   lines, parseable by a consumer;
//! - `JsonFileSink` produces a report envelope v1 whose wire bytes
//!   round-trip through `serde_json` preserving the full typed
//!   provenance/uncertainty surface;
//! - sinks are independent: each is constructed, named, and written
//!   in isolation; no shared state, no coordinator.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysdhardener_core::{
    CONCISE_WARNING, Capability, ConciseFileSink, DetailedFileSink, Finding, JsonFileSink,
    OutputSink, Report, RestrictAddressFamilies, aggregate_address_family_evidence,
    parse_fixture_v1, recommend_restrict_address_families,
};

fn recommend(path: &str, visibility: Capability) -> Finding {
    let bytes = fs::read(path).expect("fixture must be readable");
    let parsed = parse_fixture_v1(&bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    recommend_restrict_address_families(&bundle, visibility, &RestrictAddressFamilies::record())
        .expect("candidate must surface")
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tempdir(label: &str) -> RemoveDirOnDrop {
    let pid: u64 = u64::from(std::process::id());
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir_name: String = format!("sysdhardener-sink-happy-{label}-{pid}-{seq}.d");
    let path: PathBuf = std::env::temp_dir().join(dir_name);
    fs::create_dir_all(&path).expect("unique tempdir must be creatable");
    RemoveDirOnDrop { path }
}

struct RemoveDirOnDrop {
    path: PathBuf,
}

impl RemoveDirOnDrop {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn detailed_file_sink_writes_machine_parsable_text_to_unique_path() {
    let temp: RemoveDirOnDrop = unique_tempdir("detailed");
    let path: PathBuf = temp.path().join("findings.txt");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = DetailedFileSink::new(&path, std::slice::from_ref(&finding));
    assert_eq!(sink.name(), "detailed");
    sink.write()
        .expect("write must succeed against a valid path");
    let bytes: Vec<u8> = fs::read(&path).expect("consumer must read the produced file");
    let text: &str = std::str::from_utf8(&bytes).expect("detailed output must be utf-8");
    assert!(
        text.contains("RestrictAddressFamilies"),
        "detailed text must include the directive: {text}"
    );
    assert!(
        text.contains("not_observed_families"),
        "detailed text must label the not-observed families field: {text}"
    );
    assert!(
        text.contains("recommended_families"),
        "detailed text must label the recommended families field: {text}"
    );
    assert!(
        text.contains("coverage"),
        "detailed text must label coverage: {text}"
    );
    assert!(
        text.contains("compatibility"),
        "detailed text must label compatibility: {text}"
    );
    assert!(
        text.contains("validation_procedure"),
        "detailed text must label the validation procedure: {text}"
    );
    assert!(
        text.contains("source_ids"),
        "detailed text must label source_ids: {text}"
    );
    assert!(
        !text.contains("sysdhardener-sink-happy-"),
        "host path must not appear in the detailed text: {text}"
    );
}

#[test]
fn concise_file_sink_writes_warning_then_only_settings() {
    let temp: RemoveDirOnDrop = unique_tempdir("concise");
    let path: PathBuf = temp.path().join("hardening.conf");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = ConciseFileSink::new(&path, std::slice::from_ref(&finding))
        .expect("construction must accept a valid path");
    assert_eq!(sink.name(), "concise");
    sink.write()
        .expect("write must succeed against a valid path");
    let bytes: Vec<u8> = fs::read(&path).expect("consumer must read the produced file");
    let text: &str = std::str::from_utf8(&bytes).expect("concise output must be utf-8");
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        !lines.is_empty(),
        "concise file must carry at least the warning line"
    );
    assert_eq!(
        lines.first().copied(),
        Some(CONCISE_WARNING),
        "line 0 must equal CONCISE_WARNING exactly: {lines:?}"
    );
    let setting_lines: Vec<&str> = lines.get(1..).unwrap_or_default().to_vec();
    assert_eq!(setting_lines.len(), 1, "one finding -> one setting line");
    let setting: &str = setting_lines.first().copied().expect("one setting");
    let (directive, value): (&str, &str) = setting
        .split_once('=')
        .expect("concise setting must split on '='");
    assert_eq!(directive, "RestrictAddressFamilies");
    assert!(!value.trim().is_empty(), "setting value must be non-empty");
    let full_text: String = lines.join("\n");
    assert!(!full_text.contains('#') || full_text.contains(CONCISE_WARNING));
    let setting_line_only: &str = setting;
    assert!(!setting_line_only.contains("trace"));
    assert!(!setting_line_only.contains("WARNING"));
    assert!(!setting_line_only.contains("TODO"));
}

#[test]
fn json_file_sink_writes_report_envelope_v1_round_trippable() {
    let temp: RemoveDirOnDrop = unique_tempdir("json");
    let path: PathBuf = temp.path().join("report.json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction must accept a valid path");
    assert_eq!(sink.name(), "json");
    sink.write()
        .expect("write must succeed against a valid path");
    let bytes: Vec<u8> = fs::read(&path).expect("consumer must read the produced file");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("JSON must parse as the v1 envelope");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_i64),
        Some(1),
        "schema_version must be 1 in the wire envelope: {value}"
    );
    let findings: &Vec<serde_json::Value> = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .expect("findings must be an array");
    assert_eq!(findings.len(), 1, "one finding carried in the envelope");
    let f: &serde_json::Value = findings.first().expect("one finding");
    assert_eq!(
        f.get("directive").and_then(serde_json::Value::as_str),
        Some("RestrictAddressFamilies")
    );
    assert!(
        f.get("observed_families")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "observed_families must serialize: {f}"
    );
    assert!(
        f.get("recommended_families")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "recommended_families must serialize: {f}"
    );
    assert!(
        f.get("not_observed_families")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "not_observed_families must serialize: {f}"
    );
    assert!(
        f.get("coverage")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "coverage must serialize: {f}"
    );
    assert!(
        f.get("event_loss")
            .and_then(|v| v.get("seen_events"))
            .and_then(serde_json::Value::as_i64)
            .is_some(),
        "event_loss.seen_events must serialize: {f}"
    );
    assert!(
        f.get("compatibility_risk")
            .and_then(|v| v.get("source_ref"))
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "compatibility_risk.source_ref must serialize: {f}"
    );
    assert!(
        f.get("validation_procedure").is_some(),
        "validation_procedure must serialize: {f}"
    );
    let source_ids: &Vec<serde_json::Value> = f
        .get("source_ids")
        .and_then(serde_json::Value::as_array)
        .expect("source_ids must serialize as an array");
    assert!(
        !source_ids.is_empty(),
        "at least one source_id must persist"
    );
    for sid in source_ids {
        let s: &str = sid.as_str().expect("source_id must serialize as a string");
        assert!(
            s.starts_with("SRC-"),
            "source_id must retain its registry prefix: {s}"
        );
    }
    let _ = finding;
}
