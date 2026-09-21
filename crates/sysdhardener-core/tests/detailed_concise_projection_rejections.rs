//! Rejection-path tests for the canonical detailed and concise
//! projections.
//!
//! Locked invariants:
//! - a concise setting that does not map back to a finding's
//!   `recommended_families` is rejected with a typed error
//!   (unlinked setting invariant);
//! - the concise projection must carry `CONCISE_WARNING` exactly
//!   once as its first line;
//! - the projection surface never panics, never re-runs the
//!   recommendation, and never silently drops a setting;
//! - non-canonical/unsupported recommended-family slices are
//!   rejected with `UnlinkedConciseSetting { finding_index: Some(i) }`
//!   and never silently rewritten into a sentinel setting line.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public projection contract"
)]

use std::fs;

use sysdhardener_core::{
    AddressFamily, CONCISE_WARNING, Capability, CompatibilityRisk, ContradictionCondition,
    CoverageQuality, FindingBasis, RestrictAddressFamilies, SourceId,
    aggregate_address_family_evidence, finding_synthetic_for_test, parse_fixture_v1,
    project_concise, recommend_restrict_address_families,
};

fn borrowed_risk_from_canonical_pipeline() -> CompatibilityRisk {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "risk-borrow", "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0, "coverage": "unknown", "seen_events": 0,
        "dropped_events": 0, "events": []
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must surface");
    finding.compatibility_risk().clone()
}

fn recommend(path: &str, visibility: Capability) -> sysdhardener_core::Finding {
    let bytes = fs::read(path).expect("fixture must be readable");
    let parsed = parse_fixture_v1(&bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    recommend_restrict_address_families(&bundle, visibility, &RestrictAddressFamilies::record())
        .expect("candidate must surface")
}

fn synthetic_finding(recommended: Vec<AddressFamily>) -> sysdhardener_core::Finding {
    finding_synthetic_for_test(
        "RestrictAddressFamilies",
        FindingBasis::Observation {
            observed: recommended.clone(),
        },
        recommended.clone(),
        recommended,
        Vec::new(),
        CoverageQuality::Complete,
        Vec::<ContradictionCondition>::new(),
        borrowed_risk_from_canonical_pipeline(),
        vec![SourceId::from_static("SRC-01")],
        Vec::<String>::new(),
    )
}

#[test]
fn empty_findings_surface_unlinked_setting_rejection() {
    let err = project_concise(&[]).expect_err("empty findings must surface a typed rejection");
    let discriminant = format!("{err:?}");
    assert!(
        discriminant.contains("UnlinkedConciseSetting"),
        "empty findings must surface the UnlinkedConciseSetting discriminant, got: {discriminant}"
    );
    assert!(
        discriminant.contains("None"),
        "empty findings must carry finding_index = None, got: {discriminant}"
    );
}

#[test]
fn empty_observation_finding_with_no_recommended_families_rejected_typed() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "empty", "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0, "coverage": "unknown", "seen_events": 0,
        "dropped_events": 0, "events": []
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("empty fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must surface");
    let err = project_concise(&[finding]).expect_err(
        "a finding with empty recommended_families must surface an UnlinkedConciseSetting rejection",
    );
    let discriminant = format!("{err:?}");
    assert!(
        discriminant.contains("UnlinkedConciseSetting"),
        "empty-recommended finding must surface UnlinkedConciseSetting, got: {discriminant}"
    );
    assert!(
        discriminant.contains("Some(0)"),
        "the rejection must point at the offending finding index, got: {discriminant}"
    );
}

#[test]
fn warning_constant_exactly_once_and_first_line() {
    let happy = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let concise = project_concise(&[happy]).expect("happy projection must succeed");
    let lines: Vec<String> = concise.lines().to_vec();
    assert!(!lines.is_empty());
    assert_eq!(lines.first().map(String::as_str), Some(CONCISE_WARNING));
    assert_eq!(
        lines
            .iter()
            .filter(|line| **line == CONCISE_WARNING)
            .count(),
        1,
        "the warning line must appear exactly once in the concise projection"
    );
}

#[test]
fn warning_constant_is_non_empty_and_distinct_from_settings() {
    assert!(!CONCISE_WARNING.is_empty());
    assert!(!CONCISE_WARNING.contains('='));
    assert!(!CONCISE_WARNING.contains("RestrictAddressFamilies"));
}

#[test]
fn rejected_projection_does_not_panic_on_prompt_shaped_finding_metadata() {
    let err = project_concise(&[]).expect_err("empty must reject");
    let discriminant = format!("{err:?}");
    assert!(!discriminant.contains("ignore previous"));
    assert!(!discriminant.contains("apply"));
    assert!(!discriminant.contains("TODO"));
}

#[test]
fn non_canonical_recommended_slice_is_rejected_with_some_finding_index() {
    let finding = synthetic_finding(Vec::new());
    let err = project_concise(&[finding])
        .expect_err("an empty recommended slice must surface UnlinkedConciseSetting");
    let discriminant = format!("{err:?}");
    assert!(
        discriminant.contains("UnlinkedConciseSetting"),
        "empty recommended slice must surface UnlinkedConciseSetting, got: {discriminant}"
    );
    assert!(
        discriminant.contains("Some(0)"),
        "empty recommended slice must carry finding_index = Some(0), got: {discriminant}"
    );
}

#[test]
fn second_finding_with_empty_slice_reports_its_index_not_zero() {
    let happy = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let happy_concise = project_concise(std::slice::from_ref(&happy)).expect("happy projection");
    assert!(!happy_concise.lines().is_empty());
    let bad_finding = synthetic_finding(Vec::new());
    let err = project_concise(&[happy, bad_finding]).expect_err(
        "the second finding's empty slice must surface UnlinkedConciseSetting { Some(1) }",
    );
    let discriminant = format!("{err:?}");
    assert!(
        discriminant.contains("Some(1)"),
        "second finding's index must surface as Some(1), got: {discriminant}"
    );
}

#[test]
fn every_non_empty_family_combination_renders_a_setting_line() {
    // The concise setting is rendered generically from the
    // recommended allow-list: any non-empty combination the
    // recommendation produces (including combinations the fixture
    // slice never exercised, e.g. unix+inet+inet6+netlink from a
    // live observation) is representable. Only an empty slice is
    // rejected.
    let slices: &[&[AddressFamily]] = &[
        &[AddressFamily::Unix],
        &[AddressFamily::Inet],
        &[AddressFamily::Unix, AddressFamily::Inet],
        &[AddressFamily::Unix, AddressFamily::Inet6],
        &[
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6,
        ],
        &[AddressFamily::Inet, AddressFamily::Inet6],
        &[AddressFamily::Inet, AddressFamily::Unix],
        &[AddressFamily::Packet],
        &[
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6,
            AddressFamily::Netlink,
        ],
        &[AddressFamily::Netlink],
    ];
    for slice in slices {
        let finding = synthetic_finding(slice.to_vec());
        let concise =
            project_concise(&[finding]).expect("any non-empty recommended slice must project");
        let setting = concise.lines().last().expect("warning + one setting");
        assert!(
            setting.starts_with("RestrictAddressFamilies="),
            "setting must carry the directive, got: {setting:?}"
        );
        assert!(
            !setting.contains("__UNLINKED__"),
            "the projection must never emit a sentinel line: {setting:?}"
        );
    }
}

#[test]
fn empty_recommended_slice_is_rejected_by_projection() {
    let finding = synthetic_finding(Vec::new());
    let err = project_concise(&[finding])
        .expect_err("an empty recommended slice must surface UnlinkedConciseSetting");
    let discriminant = format!("{err:?}");
    assert!(
        discriminant.contains("UnlinkedConciseSetting"),
        "empty slice must surface UnlinkedConciseSetting, got: {discriminant}"
    );
}

#[test]
fn concise_projection_never_emits_a_sentinel_or_unlinked_setting_line() {
    // Three findings whose recommended slices span canonical,
    // empty, and non-canonical: the first two must surface
    // settings; the third must be rejected with the typed
    // discriminant before any sentinel setting line can be
    // emitted.
    let happy = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let degraded = recommend("tests/fixtures/degraded.json", Capability::DegradedNonRoot);
    let contradictory = recommend(
        "tests/fixtures/contradictory.json",
        Capability::ExpectedRoot,
    );
    let findings = [happy, degraded, contradictory];
    let concise = project_concise(&findings).expect("all canonical findings must project");
    for line in concise.lines() {
        assert!(
            !line.contains("__UNLINKED__"),
            "the projection must never emit a __UNLINKED__ sentinel line: {line:?}"
        );
        assert!(
            !line.contains("UNLINKED"),
            "the projection must never emit any UNLINKED marker: {line:?}"
        );
    }
}
