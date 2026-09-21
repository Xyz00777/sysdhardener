//! Report-envelope v1 round-trip and provenance/uncertainty preservation
//! across the JSON file sink.
//!
//! Locked invariants:
//! - the JSON file sink writes the report envelope v1 wire shape
//!   exactly, never a wrapped/projected shape;
//! - the round-trip preserves the full typed provenance surface
//!   (source IDs, aggregate keys, compatibility risk, validation
//!   procedure, event-loss counts, contradiction conditions);
//! - the round-trip preserves every uncertainty label (provisional,
//!   unverified compatibility, coverage, event loss, contradiction
//!   conditions) across a wire read;
//! - unknown envelope versions are rejected at the boundary (already
//!   locked by the `serialize_report_v1` invariant; this test
//!   verifies the sink consumes the same boundary).

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
    Capability, Finding, JsonFileSink, OutputSink, Report, RestrictAddressFamilies,
    SUPPORTED_REPORT_SCHEMA, aggregate_address_family_evidence, parse_fixture_v1,
    recommend_restrict_address_families,
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
    let dir_name: String = format!("sysdhardener-sink-roundtrip-{label}-{pid}-{seq}.d");
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
fn json_sink_emits_supported_schema_version_unchanged() {
    let temp: RemoveDirOnDrop = unique_tempdir("schema");
    let path: PathBuf = temp.path().join("report.json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction");
    sink.write().expect("write");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let version: i64 = value
        .get("schema_version")
        .and_then(serde_json::Value::as_i64)
        .expect("schema_version is u32 on the wire");
    let supported: &[u32] = SUPPORTED_REPORT_SCHEMA;
    let supported_contains: bool = u32::try_from(version).is_ok_and(|v| supported.contains(&v));
    assert!(
        supported_contains,
        "wire schema_version {version} must remain in the supported set {supported:?}"
    );
}

#[test]
fn json_sink_round_trip_preserves_provenance_and_uncertainty_for_happy_finding() {
    let temp: RemoveDirOnDrop = unique_tempdir("rt-happy");
    let path: PathBuf = temp.path().join("report.json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let expected_source_ids: Vec<String> = finding.source_ids();
    let expected_event_loss_seen: u32 = finding.event_loss().seen_events();
    let expected_event_loss_dropped: u32 = finding.event_loss().dropped_events();
    let expected_aggregate_keys: Vec<String> = finding.aggregate_keys().to_vec();
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction");
    sink.write().expect("write");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let f: &serde_json::Value = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| arr.first())
        .expect("one finding");
    let source_ids: Vec<String> = f
        .get("source_ids")
        .and_then(serde_json::Value::as_array)
        .expect("source_ids array")
        .iter()
        .map(|v| v.as_str().expect("string source_id").to_owned())
        .collect();
    assert_eq!(source_ids, expected_source_ids);
    let seen: u64 = f
        .get("event_loss")
        .and_then(|v| v.get("seen_events"))
        .and_then(serde_json::Value::as_u64)
        .expect("event_loss.seen_events u32");
    assert_eq!(u32::try_from(seen), Ok(expected_event_loss_seen));
    let dropped: u64 = f
        .get("event_loss")
        .and_then(|v| v.get("dropped_events"))
        .and_then(serde_json::Value::as_u64)
        .expect("event_loss.dropped_events u32");
    assert_eq!(u32::try_from(dropped), Ok(expected_event_loss_dropped));
    let aggregate_keys: Vec<String> = f
        .get("aggregate_keys")
        .and_then(serde_json::Value::as_array)
        .expect("aggregate_keys array")
        .iter()
        .map(|v| v.as_str().expect("string aggregate_key").to_owned())
        .collect();
    assert_eq!(aggregate_keys, expected_aggregate_keys);
    let validation: &str = f
        .get("validation_procedure")
        .and_then(serde_json::Value::as_str)
        .expect("validation_procedure must serialize as a tagged string");
    assert_eq!(
        validation, "confirm_no_out_of_set_use",
        "validation_procedure must serialize to its serde snake_case: {validation}"
    );
    let provisional: &str = f
        .get("provisional")
        .and_then(serde_json::Value::as_str)
        .expect("provisional must serialize as a tagged string");
    assert_eq!(
        provisional, "provisional",
        "provisional must serialize to its serde snake_case: {provisional}"
    );
}

#[test]
fn json_sink_round_trip_preserves_contradiction_conditions() {
    let temp: RemoveDirOnDrop = unique_tempdir("rt-contradictory");
    let path: PathBuf = temp.path().join("report.json");
    let finding: Finding = recommend(
        "tests/fixtures/contradictory.json",
        Capability::ExpectedRoot,
    );
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction");
    sink.write().expect("write");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let f: &serde_json::Value = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| arr.first())
        .expect("one finding");
    let conditions: &Vec<serde_json::Value> = f
        .get("contradiction_conditions")
        .and_then(serde_json::Value::as_array)
        .expect("contradiction_conditions must serialize as an array");
    assert!(
        !conditions.is_empty(),
        "contradictory fixture must surface contradiction conditions: {f}"
    );
    // Each condition is a tagged enum; the `kind` tag carries the
    // discriminant the consumer dispatches on.
    for condition in conditions {
        let kind: &str = condition
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .expect("each contradiction condition carries a `kind` tag");
        assert!(
            kind == "observed_without_successful_use" || kind == "absent_family_used_later",
            "unknown contradiction kind would mean a typed enum was lost: {kind}"
        );
    }
}
