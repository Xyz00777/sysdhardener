//! Pipeline tests for empty findings (compute targets, 0 socket/capability events).
//!
//! Locked invariants:
//! - An application with 0 socket events and 0 capability events (compute daemon)
//!   produces 0 findings;
//! - The analysis pipeline succeeds without error;
//! - The detailed view renders "(no findings)";
//! - The concise view contains exactly the warning line and no settings;
//! - `ConciseFileSink::from_projection` succeeds and writes the warning;
//! - Report JSON contains an empty findings array.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public pipeline contract"
)]

use sysdhardener_core::{
    CONCISE_WARNING, Capability, ConciseFileSink, ConciseProjection, Fixture, OutputSink,
    RestrictAddressFamilies, run_analysis_from_fixture,
};

#[test]
fn empty_events_fixture_runs_analysis_successfully_with_zero_findings() {
    let fixture = Fixture::from_events(Vec::new());
    let compatibility = RestrictAddressFamilies::record();

    let summary = run_analysis_from_fixture(
        &fixture,
        Capability::ExpectedRoot,
        &compatibility,
        100,
        None,
        &[],
    )
    .expect("analysis pipeline must succeed for compute/idle target with 0 findings");

    assert!(
        summary.findings.is_empty(),
        "findings must be empty for 0 socket/capability events"
    );
    assert_eq!(
        summary.concise.lines(),
        &[CONCISE_WARNING],
        "concise projection must contain only the warning line"
    );
    assert!(
        summary.detailed.entries().is_empty(),
        "detailed projection must have 0 entries"
    );

    let report_json: serde_json::Value =
        serde_json::from_slice(&summary.report_bytes).expect("report bytes must be valid JSON");
    let findings_array = report_json
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .expect("report must have findings array");
    assert!(
        findings_array.is_empty(),
        "report JSON must have empty findings array"
    );
}

#[test]
fn concise_file_sink_from_projection_writes_warning_for_empty_projection() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sysdhardener-test-concise-empty-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let conf_path = temp_dir.join("hardening.conf");

    let projection = ConciseProjection::empty();
    let sink = ConciseFileSink::from_projection(&conf_path, &projection);
    sink.write().expect("sink write must succeed");

    let content = std::fs::read_to_string(&conf_path).expect("read written file");
    assert_eq!(
        content.trim(),
        CONCISE_WARNING,
        "written concise file must contain only the warning"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn detailed_file_sink_writes_no_findings_block_for_empty_findings() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sysdhardener-test-detailed-empty-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    let detailed_path = temp_dir.join("findings.txt");

    let sink = sysdhardener_core::DetailedFileSink::new(&detailed_path, &[]);
    sink.write().expect("detailed sink write must succeed");

    let content = std::fs::read_to_string(&detailed_path).expect("read written file");
    assert!(
        content.contains("(no findings)"),
        "detailed file must report (no findings), got: {content}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
