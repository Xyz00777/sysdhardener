//! Happy-path contract tests for the single provisional
//! `RestrictAddressFamilies=` recommendation.
//!
//! Locked invariants:
//! - the canonical fixture recommends exactly the documented
//!   address-family set (observed successful use);
//! - the candidate is always surfaced, even for empty / low-coverage /
//!   dropped-event / degraded-visibility evidence;
//! - every candidate carries all mandatory labels: not observed,
//!   unverified/provisional, observation coverage, event loss,
//!   contradiction conditions, compatibility risk, validation procedure;
//! - source IDs and aggregate keys remain linked on the finding;
//! - visibility degrades effective coverage; root alone never implies
//!   complete observation.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public recommendation contract"
)]

use std::fs;

use proptest::prelude::*;
use sysdhardener_core::{
    AddressFamily, AddressFamilyBundle, Capability, ContradictionCondition, CoverageQuality,
    Finding, FindingBasis, ProvisionalStatus, RestrictAddressFamilies, ValidationProcedure,
    aggregate_address_family_evidence, parse_fixture_v1, recommend_restrict_address_families,
};

fn fixture(path: &str) -> sysdhardener_core::Fixture {
    let bytes = fs::read(path).expect("canonical fixture must be readable");
    parse_fixture_v1(&bytes).expect("canonical fixture must parse")
}

fn recommend(path: &str, visibility: Capability) -> (AddressFamilyBundle, Finding) {
    let parsed = fixture(path);
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed)
        .expect("fixture must aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        visibility,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must always surface");
    (bundle, finding)
}

#[test]
fn canonical_fixture_recommends_documented_set_with_all_mandatory_labels() {
    let (_bundle, finding) = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    assert_eq!(finding.directive(), "RestrictAddressFamilies");
    assert_eq!(
        finding.recommended_families(),
        vec![
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6,
        ]
    );
    assert_eq!(
        finding.observed_families(),
        vec![
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6,
        ]
    );
    assert_eq!(
        finding.not_observed_families(),
        vec![AddressFamily::Netlink, AddressFamily::Packet]
    );
    assert_eq!(
        finding.basis(),
        &FindingBasis::Absence {
            not_observed: vec![AddressFamily::Netlink, AddressFamily::Packet],
        }
    );
    assert_eq!(finding.provisional(), ProvisionalStatus::Provisional);
    assert_eq!(finding.coverage(), CoverageQuality::Complete);
    assert_eq!(finding.event_loss().seen_events(), 3);
    assert_eq!(finding.event_loss().dropped_events(), 0);
    assert!(!finding.event_loss().has_loss());
    #[rustfmt::skip]
    assert_eq!(
        finding.contradiction_conditions(),
        &[
            ContradictionCondition::AbsentFamilyUsedLater { family: AddressFamily::Netlink },
            ContradictionCondition::AbsentFamilyUsedLater { family: AddressFamily::Packet },
        ]
    );
    assert!(finding.compatibility_risk().unverified());
    assert_eq!(finding.compatibility_risk().source_ref().as_str(), "SRC-02");
    assert_eq!(
        finding.validation_procedure(),
        ValidationProcedure::ConfirmNoOutOfSetUse
    );
}

#[test]
fn happy_finding_links_sources_and_aggregate_keys() {
    let (bundle, finding) = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    assert_eq!(finding.source_ids(), vec!["SRC-01".to_owned()]);
    let keys: Vec<String> = finding.aggregate_keys().to_vec();
    assert_eq!(keys.len(), 3);
    for family in [
        AddressFamily::Unix,
        AddressFamily::Inet,
        AddressFamily::Inet6,
    ] {
        let entry = bundle.get(family).expect("observed family must aggregate");
        assert!(
            keys.contains(&entry.key().to_owned()),
            "finding must link aggregate key for {family:?}"
        );
    }
    for key in &keys {
        assert!(key.starts_with("af="), "key must stay explicit: {key}");
    }
}

#[test]
fn empty_observation_still_surfaces_candidate_with_all_labels() {
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
    .expect("empty observation must still surface the candidate");
    assert!(finding.recommended_families().is_empty());
    assert!(finding.observed_families().is_empty());
    assert_eq!(finding.not_observed_families().len(), 5);
    assert_eq!(finding.coverage(), CoverageQuality::Unknown);
    assert_eq!(finding.contradiction_conditions().len(), 5);
    assert!(finding.source_ids().is_empty());
    assert!(finding.aggregate_keys().is_empty());
    assert_eq!(finding.provisional(), ProvisionalStatus::Provisional);
    assert!(finding.compatibility_risk().unverified());
}

#[test]
fn degraded_visibility_degrades_coverage_even_on_complete_claim() {
    let (_, root) = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    assert_eq!(root.coverage(), CoverageQuality::Complete);
    let (_, non_root) = recommend("tests/fixtures/happy.json", Capability::DegradedNonRoot);
    assert_eq!(non_root.coverage(), CoverageQuality::Degraded);
    let (_, unknown) = recommend("tests/fixtures/happy.json", Capability::Unknown);
    assert_eq!(unknown.coverage(), CoverageQuality::Degraded);
}

#[test]
fn dropped_events_are_carried_and_never_hide_the_candidate() {
    let (_bundle, finding) = recommend("tests/fixtures/with-loss.json", Capability::ExpectedRoot);
    assert_eq!(finding.event_loss().seen_events(), 2);
    assert_eq!(finding.event_loss().dropped_events(), 1);
    assert!(finding.event_loss().has_loss());
    assert_eq!(finding.coverage(), CoverageQuality::Degraded);
    assert_eq!(
        finding.recommended_families(),
        vec![AddressFamily::Unix, AddressFamily::Inet]
    );
    #[rustfmt::skip]
    assert_eq!(
        finding.not_observed_families(),
        vec![AddressFamily::Inet6, AddressFamily::Netlink, AddressFamily::Packet]
    );
}

#[test]
fn low_coverage_never_hides_the_candidate() {
    let (_bundle, finding) = recommend("tests/fixtures/degraded.json", Capability::DegradedNonRoot);
    assert_eq!(finding.coverage(), CoverageQuality::Degraded);
    assert_eq!(finding.recommended_families(), vec![AddressFamily::Unix]);
    assert_eq!(finding.not_observed_families().len(), 4);
    assert_eq!(finding.provisional(), ProvisionalStatus::Provisional);
    assert!(finding.compatibility_risk().unverified());
}

#[test]
fn contradictory_evidence_surfaces_candidate_with_typed_contradictions() {
    let (_bundle, finding) = recommend(
        "tests/fixtures/contradictory.json",
        Capability::ExpectedRoot,
    );
    // netlink was observed with an error outcome: failed exploratory
    // syscalls are not successful use, so it is excluded from the
    // allow-list and surfaced as a contradiction condition.
    assert_eq!(
        finding.observed_families(),
        vec![AddressFamily::Unix, AddressFamily::Netlink]
    );
    assert_eq!(finding.recommended_families(), vec![AddressFamily::Unix]);
    assert_eq!(
        finding.not_observed_families(),
        vec![
            AddressFamily::Inet,
            AddressFamily::Inet6,
            AddressFamily::Packet
        ]
    );
    assert_eq!(
        finding.contradiction_conditions(),
        &[
            ContradictionCondition::ObservedWithoutSuccessfulUse {
                family: AddressFamily::Netlink,
                representative_event_id: "evt-002".to_owned(),
            },
            ContradictionCondition::AbsentFamilyUsedLater {
                family: AddressFamily::Inet,
            },
            ContradictionCondition::AbsentFamilyUsedLater {
                family: AddressFamily::Inet6,
            },
            ContradictionCondition::AbsentFamilyUsedLater {
                family: AddressFamily::Packet,
            },
        ]
    );
    assert_eq!(
        finding.source_ids(),
        vec!["SRC-01".to_owned(), "SRC-02".to_owned()]
    );
}

#[test]
fn finding_serializes_all_mandatory_label_fields() {
    let (_bundle, finding) = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let json = serde_json::to_string(&finding).expect("finding must serialize");
    for label in "directive basis observed_families recommended_families not_observed_families provisional coverage event_loss contradiction_conditions compatibility_risk validation_procedure source_ids aggregate_keys"
        .split_whitespace()
    {
        assert!(json.contains(&format!("\"{label}\"")), "finding JSON must carry {label}");
    }
    assert!(json.contains("\"confirm_no_out_of_set_use\""));
    assert!(json.contains("\"SRC-02\""));
}

proptest! {
    #[test]
    fn all_event_permutations_produce_byte_identical_finding(
        order in prop::sample::select(vec![
            [0usize, 1, 2], [0, 2, 1], [1, 0, 2],
            [1, 2, 0], [2, 0, 1], [2, 1, 0],
        ])
    ) {
        let parsed = fixture("tests/fixtures/happy.json");
        let baseline = aggregate_address_family_evidence(parsed.events(), &parsed)
            .expect("canonical fixture must aggregate");
        let baseline_finding = recommend_restrict_address_families(
            &baseline,
            Capability::ExpectedRoot,
            &RestrictAddressFamilies::record(),
        )
        .expect("baseline must recommend");
        let events = order
            .iter()
            .map(|index| parsed.events().get(*index).expect("fixed index").clone())
            .collect::<Vec<_>>();
        let shuffled = aggregate_address_family_evidence(&events, &parsed)
            .expect("permuted fixture must aggregate");
        let shuffled_finding = recommend_restrict_address_families(
            &shuffled,
            Capability::ExpectedRoot,
            &RestrictAddressFamilies::record(),
        )
        .expect("permuted must recommend");
        let a = serde_json::to_vec(&baseline_finding).expect("baseline serializes");
        let b = serde_json::to_vec(&shuffled_finding).expect("shuffled serializes");
        prop_assert_eq!(a, b, "finding must be permutation-invariant");
    }
}
