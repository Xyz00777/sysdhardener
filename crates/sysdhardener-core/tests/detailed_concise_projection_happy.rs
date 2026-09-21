//! Happy-path contract tests for the canonical detailed and concise
//! projections.
//!
//! Locked invariants:
//! - both projections transform the supplied immutable `Finding`
//!   collection;
//! - the detailed projection lists found/not-found status, outcome,
//!   evidence, provenance, coverage, compatibility, and validation
//!   guidance for every finding;
//! - the concise projection carries exactly one file-level warning
//!   line (`CONCISE_WARNING`) followed only by settings;
//! - each concise setting maps 1:1 back to a finding's
//!   `recommended_families` (no orphan settings);
//! - assertions exercise typed fields and emitted output, not source layout.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public projection contract"
)]

use std::fs;

use sysdhardener_core::{
    AddressFamily, CONCISE_WARNING, Capability, ConciseProjection, DetailedProjection, Finding,
    Report, RestrictAddressFamilies, aggregate_address_family_evidence, parse_fixture_v1,
    project_concise, project_detailed, recommend_restrict_address_families, serialize_report_v1,
};

fn recommend(path: &str, visibility: Capability) -> Finding {
    let bytes = fs::read(path).expect("fixture must be readable");
    let parsed = parse_fixture_v1(&bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    recommend_restrict_address_families(&bundle, visibility, &RestrictAddressFamilies::record())
        .expect("candidate must surface")
}

fn recommend_happy() -> Finding {
    recommend("tests/fixtures/happy.json", Capability::ExpectedRoot)
}

fn recommend_degraded() -> Finding {
    recommend("tests/fixtures/degraded.json", Capability::DegradedNonRoot)
}

fn recommend_contradictory() -> Finding {
    recommend(
        "tests/fixtures/contradictory.json",
        Capability::ExpectedRoot,
    )
}

fn lines_of(concise: &ConciseProjection) -> Vec<String> {
    concise.lines().to_vec()
}

fn parse_concise_setting(line: &str) -> (&str, &str) {
    let (directive, value) = line
        .split_once('=')
        .expect("concise setting must contain '='");
    (directive, value)
}

fn parse_family_list(value: &str) -> Vec<AddressFamily> {
    value
        .split_whitespace()
        .map(|tag| match tag {
            "AF_UNIX" => AddressFamily::Unix,
            "AF_INET" => AddressFamily::Inet,
            "AF_INET6" => AddressFamily::Inet6,
            "AF_NETLINK" => AddressFamily::Netlink,
            "AF_PACKET" => AddressFamily::Packet,
            other => panic!("unexpected family tag {other:?}"),
        })
        .collect()
}

#[test]
fn detailed_projection_carries_full_typed_label_set_for_each_finding() {
    let finding = recommend_happy();
    let detailed: DetailedProjection = project_detailed(std::slice::from_ref(&finding));
    let entries: &[sysdhardener_core::DetailedEntry] = detailed.entries();
    assert_eq!(entries.len(), 1);
    let entry: &sysdhardener_core::DetailedEntry = entries.first().expect("one entry");
    assert_eq!(entry.directive(), "RestrictAddressFamilies");
    assert_eq!(entry.basis(), finding.basis());
    assert_eq!(entry.observed_families(), finding.observed_families());
    assert_eq!(entry.recommended_families(), finding.recommended_families());
    assert_eq!(
        entry.not_observed_families(),
        finding.not_observed_families()
    );
    assert_eq!(entry.provisional(), finding.provisional());
    assert_eq!(entry.coverage(), finding.coverage());
    assert_eq!(
        entry.event_loss().seen_events(),
        finding.event_loss().seen_events()
    );
    assert_eq!(
        entry.event_loss().dropped_events(),
        finding.event_loss().dropped_events()
    );
    assert_eq!(
        entry.contradiction_conditions(),
        finding.contradiction_conditions()
    );
    assert_eq!(
        entry.compatibility_risk().source_ref(),
        finding.compatibility_risk().source_ref()
    );
    assert_eq!(entry.validation_procedure(), finding.validation_procedure());
    assert_eq!(entry.source_ids(), finding.source_ids());
    assert_eq!(entry.aggregate_keys(), finding.aggregate_keys());
    assert_eq!(entry.found(), Some("found"));
    assert!(!entry.validation_procedure_text().is_empty());
    assert!(entry.compatibility_summary().contains("SRC-02"));
}

#[test]
fn detailed_projection_marks_absent_finding_against_compatibility_record() {
    let degraded = recommend_degraded();
    let detailed: DetailedProjection = project_detailed(std::slice::from_ref(&degraded));
    let entry: &sysdhardener_core::DetailedEntry = detailed.entries().first().expect("one entry");
    assert_eq!(entry.recommended_families(), &[AddressFamily::Unix]);
    assert_eq!(
        entry.not_observed_families(),
        &[
            AddressFamily::Inet,
            AddressFamily::Inet6,
            AddressFamily::Netlink,
            AddressFamily::Packet
        ]
    );
    assert_eq!(entry.found(), Some("found"));
    assert!(entry.coverage_summary().contains("degraded"));
}

#[test]
fn concise_projection_has_warning_line_then_only_settings() {
    let finding = recommend_happy();
    let concise: ConciseProjection =
        project_concise(std::slice::from_ref(&finding)).expect("happy projection");
    let lines: Vec<String> = lines_of(&concise);
    assert_eq!(lines.len(), 2, "warning + one setting; got {lines:?}");
    assert_eq!(lines.first().map(String::as_str), Some(CONCISE_WARNING));
    let setting: &str = lines
        .get(1)
        .map(String::as_str)
        .expect("second line is the setting");
    assert!(
        setting.starts_with("RestrictAddressFamilies="),
        "setting must begin with the directive: {setting:?}"
    );
    assert!(!setting.contains('#'));
    assert!(!setting.contains("trace"));
    assert!(!setting.contains("warning"));
    assert!(!setting.contains("WARNING"));
    assert!(!setting.contains("TODO"));
}

#[test]
fn concise_projection_emits_one_warning_for_multiple_findings() {
    let findings = [
        recommend_happy(),
        recommend_degraded(),
        recommend_contradictory(),
    ];
    let concise: ConciseProjection = project_concise(&findings).expect("projection");
    let lines: Vec<String> = lines_of(&concise);
    let warning_count: usize = lines
        .iter()
        .filter(|line| **line == CONCISE_WARNING)
        .count();

    assert_eq!(
        warning_count, 1,
        "the concise projection must contain exactly one file-level warning: {lines:?}"
    );
    assert_eq!(lines.first().map(String::as_str), Some(CONCISE_WARNING));
}

#[test]
fn every_concise_setting_maps_to_one_finding() {
    let happy = recommend_happy();
    let degraded = recommend_degraded();
    let concise: ConciseProjection =
        project_concise(&[happy.clone(), degraded.clone()]).expect("projection");
    let lines: Vec<String> = lines_of(&concise);
    assert_eq!(lines.len(), 3, "warning + two settings");
    assert_eq!(lines.first().map(String::as_str), Some(CONCISE_WARNING));
    let setting_lines: Vec<String> = lines.get(1..).unwrap_or_default().to_vec();
    let findings: Vec<Finding> = vec![happy, degraded];
    for setting in &setting_lines {
        let (directive, value) = parse_concise_setting(setting);
        assert_eq!(directive, "RestrictAddressFamilies");
        let family_list = parse_family_list(value);
        assert!(!family_list.is_empty());
        let matched = findings.iter().any(|finding| {
            finding.directive() == directive
                && finding.recommended_families() == family_list.as_slice()
        });
        assert!(
            matched,
            "concise setting {setting:?} must map to a finding's recommended_families"
        );
    }
}
#[test]
fn concise_projection_surfaces_contradictory_finding_setting() {
    let contradictory = recommend_contradictory();
    let concise: ConciseProjection =
        project_concise(std::slice::from_ref(&contradictory)).expect("projection");
    let lines: Vec<String> = lines_of(&concise);
    assert_eq!(lines.len(), 2);
    let (_, value) = lines
        .get(1)
        .map(String::as_str)
        .expect("setting line")
        .split_once('=')
        .expect("=");
    let families: Vec<AddressFamily> = parse_family_list(value);
    assert_eq!(families, contradictory.recommended_families());
}

#[test]
fn empty_findings_is_a_typed_rejection_not_silent_drop() {
    let err = project_concise(&[]).expect_err("empty must be rejected");
    let discriminant = format!("{err:?}");
    assert!(discriminant.contains("UnlinkedConciseSetting"));
    let _ = CONCISE_WARNING;
}

#[test]
fn detailed_projection_empty_findings_is_empty() {
    let detailed: DetailedProjection = project_detailed(&[]);
    assert!(detailed.entries().is_empty());
}

#[test]
fn report_v1_round_trip_with_findings_then_projections() {
    let happy = recommend_happy();
    let findings = [happy];
    let report: Report<'_> = Report::with_findings(&findings);
    let bytes: Vec<u8> = serialize_report_v1(&report).expect("report must serialize");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_i64),
        Some(1)
    );
    let detailed: DetailedProjection = project_detailed(report.findings());
    let concise: ConciseProjection = project_concise(report.findings()).expect("projection");
    assert_eq!(detailed.entries().len(), 1);
    assert_eq!(lines_of(&concise).len(), 2);
    assert_eq!(
        lines_of(&concise).first().map(String::as_str),
        Some(CONCISE_WARNING)
    );
    let _ = happy;
}

#[test]
fn concise_projection_matches_bounded_golden_for_canonical_finding() {
    let happy = recommend_happy();
    let concise: ConciseProjection =
        project_concise(std::slice::from_ref(&happy)).expect("happy projection");
    let lines: Vec<String> = lines_of(&concise);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines.first().map(String::as_str), Some(CONCISE_WARNING));
    assert_eq!(
        lines.get(1).map(String::as_str),
        Some("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
    );
    insta::assert_snapshot!("concise_canonical_happy", lines.join("\n"));
}
