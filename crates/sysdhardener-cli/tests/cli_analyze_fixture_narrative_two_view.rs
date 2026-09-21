//! Narrative two-view E2E scenarios: the release
//! binary driven through the public CLI only, asserting
//! machine-consumed structure/exit/files.
//!
//! Covered here: default two-view output, JSON-only opt-in, the
//! non-root degraded-visibility label, the contradictory fixture
//! surfacing a provisional candidate, and byte-identical repeat
//! output across distinct temp roots.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

mod common;

use std::ffi::OsStr;

use common::{dir_entries, fixture_path, run_bin, unique_tempdir};

/// The canonical `analyze-fixture` invocation for `fixture`,
/// writing the two default views plus a report envelope into
/// `output_dir`.
fn default_invocation<'a>(fixture: &'a OsStr, output_dir: &'a OsStr) -> Vec<&'a OsStr> {
    vec![
        OsStr::new("analyze-fixture"),
        fixture,
        OsStr::new("--output-dir"),
        output_dir,
    ]
}

#[test]
fn default_two_view_output_writes_detailed_and_concise_files() {
    let dir = unique_tempdir("narrative-two-view");
    let outcome = run_bin(&default_invocation(
        fixture_path("happy.json").as_os_str(),
        dir.path().as_os_str(),
    ));
    assert_eq!(outcome.code, Some(0), "stderr: {}", outcome.stderr);

    let detailed =
        std::fs::read_to_string(dir.path().join("findings.txt")).expect("findings.txt readable");
    assert!(
        detailed.contains("directive: RestrictAddressFamilies"),
        "detailed view must carry the directive machine label, got: {detailed}"
    );
    assert!(
        detailed.contains("provisional: provisional"),
        "detailed view must carry the provisional machine label, got: {detailed}"
    );

    let concise = std::fs::read_to_string(dir.path().join("hardening.conf"))
        .expect("hardening.conf readable");
    let mut lines = concise.lines();
    let warning = lines.next().expect("concise view must have a warning line");
    let setting = lines.next().expect("concise view must have a setting line");
    assert_eq!(
        lines.next(),
        None,
        "concise view must be exactly warning + one setting, got: {concise}"
    );
    assert!(
        warning.starts_with("# WARNING:"),
        "concise line 1 is the warning line, got: {concise}"
    );
    assert!(
        setting.starts_with("RestrictAddressFamilies="),
        "concise line 2 is the setting line, got: {concise}"
    );
    assert_eq!(
        dir_entries(dir.path()),
        vec!["findings.txt", "hardening.conf"]
    );
}

#[test]
fn json_only_opt_in_writes_report_envelope_and_nothing_else() {
    let dir = unique_tempdir("narrative-json-only");
    let json_path = dir.path().join("report.json");
    let happy = fixture_path("happy.json");
    let mut args = default_invocation(happy.as_os_str(), dir.path().as_os_str());
    args.extend([
        OsStr::new("--no-detailed"),
        OsStr::new("--no-concise"),
        OsStr::new("--json"),
        json_path.as_os_str(),
    ]);
    let outcome = run_bin(&args);
    assert_eq!(outcome.code, Some(0), "stderr: {}", outcome.stderr);
    assert_eq!(dir_entries(dir.path()), vec!["report.json"]);

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("report.json readable"))
            .expect("report envelope must be valid JSON");
    assert_eq!(
        report
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    let finding = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|findings| findings.first())
        .expect("findings must contain one finding");
    assert_eq!(
        finding.get("directive").and_then(serde_json::Value::as_str),
        Some("RestrictAddressFamilies")
    );
    assert_eq!(
        finding
            .get("provisional")
            .and_then(serde_json::Value::as_str),
        Some("provisional")
    );
}

#[test]
fn non_root_visibility_degrades_complete_fixture_coverage_label() {
    // The happy fixture declares wire coverage "complete" with zero
    // dropped events, so the only source of a "degraded" effective
    // coverage label is the process visibility classification: the
    // real probe runs as a non-root effective UID (DegradedNonRoot),
    // which degrades the composed coverage. This is the non-root
    // execution path; production exposes no flag that lies about UID.
    let dir = unique_tempdir("narrative-degraded-label");
    let outcome = run_bin(&default_invocation(
        fixture_path("happy.json").as_os_str(),
        dir.path().as_os_str(),
    ));
    assert_eq!(outcome.code, Some(0), "stderr: {}", outcome.stderr);

    let detailed =
        std::fs::read_to_string(dir.path().join("findings.txt")).expect("findings.txt readable");
    assert!(
        detailed.contains("coverage: degraded"),
        "non-root visibility must degrade the coverage label, got: {detailed}"
    );
    assert!(
        detailed.contains("dropped_events=0"),
        "fixture declares no event loss, so the degraded label is visibility-driven, got: {detailed}"
    );
}

#[test]
fn contradictory_fixture_surfaces_provisional_candidate_with_labels() {
    let dir = unique_tempdir("narrative-contradictory");
    let json_path = dir.path().join("report.json");
    let contradictory = fixture_path("contradictory.json");
    let mut args = default_invocation(contradictory.as_os_str(), dir.path().as_os_str());
    args.extend([OsStr::new("--json"), json_path.as_os_str()]);
    let outcome = run_bin(&args);
    assert_eq!(outcome.code, Some(0), "stderr: {}", outcome.stderr);

    let detailed =
        std::fs::read_to_string(dir.path().join("findings.txt")).expect("findings.txt readable");
    assert!(
        detailed.contains("directive: RestrictAddressFamilies"),
        "contradictory evidence must still surface the candidate, got: {detailed}"
    );
    assert!(
        detailed.contains("provisional: provisional"),
        "candidate must carry the provisional machine label, got: {detailed}"
    );
    assert!(
        detailed.contains("recommended_families: [AF_UNIX]"),
        "the provisional allow-list must be surfaced, got: {detailed}"
    );
    assert!(
        detailed.contains("observed_without_successful_use family=AF_NETLINK"),
        "the contradiction must be labeled with the machine family tag, got: {detailed}"
    );

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("report.json readable"))
            .expect("report envelope must be valid JSON");
    let contradictions = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|findings| findings.first())
        .and_then(|finding| finding.get("contradiction_conditions"))
        .and_then(serde_json::Value::as_array)
        .expect("finding must carry contradiction_conditions");
    assert!(
        contradictions
            .iter()
            .all(|condition| condition.get("kind").is_some()),
        "every contradiction condition must carry the kind machine field, got: {report}"
    );
}

#[test]
fn same_invocation_twice_in_distinct_temp_roots_is_byte_identical() {
    let dir_a = unique_tempdir("narrative-repeat-a");
    let dir_b = unique_tempdir("narrative-repeat-b");
    let json_a = dir_a.path().join("report.json");
    let json_b = dir_b.path().join("report.json");
    let happy = fixture_path("happy.json");
    let mut args_a = default_invocation(happy.as_os_str(), dir_a.path().as_os_str());
    args_a.extend([OsStr::new("--json"), json_a.as_os_str()]);
    let mut args_b = default_invocation(happy.as_os_str(), dir_b.path().as_os_str());
    args_b.extend([OsStr::new("--json"), json_b.as_os_str()]);

    let first = run_bin(&args_a);
    let second = run_bin(&args_b);
    assert_eq!(first.code, Some(0), "stderr: {}", first.stderr);
    assert_eq!(second.code, Some(0), "stderr: {}", second.stderr);

    for artifact in ["findings.txt", "hardening.conf", "report.json"] {
        let bytes_a = std::fs::read(dir_a.path().join(artifact)).expect("first artifact readable");
        let bytes_b = std::fs::read(dir_b.path().join(artifact)).expect("second artifact readable");
        assert_eq!(
            bytes_a, bytes_b,
            "{artifact} must be byte-identical across distinct temp roots"
        );
    }
}
