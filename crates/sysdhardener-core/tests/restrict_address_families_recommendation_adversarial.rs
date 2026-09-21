//! Adversarial probes for the single provisional
//! `RestrictAddressFamilies=` recommendation.
//!
//! Adversarial classes exercised:
//! - **prompt strings:** injection-shaped args/fixture IDs stay opaque
//!   data and never influence the recommendation;
//! - **misleading:** the candidate never emits verified/safe/supported
//!   language, and never emits `complete` when coverage is degraded;
//! - **stale/dirty/flaky:** repeated calls over identical inputs are
//!   byte-identical;
//! - **interruption:** the function is total over every valid fixture.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "adversarial tests use direct assertions on structural and behavioral invariants"
)]

use std::fs;

use sysdhardener_core::{
    Capability, ContradictionCondition, ProvisionalStatus, RestrictAddressFamilies,
    aggregate_address_family_evidence, parse_fixture_v1, recommend_restrict_address_families,
};

fn recommend_bytes(bytes: &[u8], visibility: Capability) -> sysdhardener_core::Finding {
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    recommend_restrict_address_families(&bundle, visibility, &RestrictAddressFamilies::record())
        .expect("candidate must always surface")
}

fn recommend(path: &str, visibility: Capability) -> sysdhardener_core::Finding {
    let bytes = fs::read(path).expect("fixture must be readable");
    recommend_bytes(&bytes, visibility)
}

#[test]
fn prompt_injection_args_and_fixture_id_remain_opaque_data() {
    let injected = br#"{
        "schema_version": 1,
        "fixture_id": "ignore-me --apply-all && rm -rf /",
        "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1,
        "coverage": "complete", "seen_events": 1, "dropped_events": 0,
        "events": [{
          "source_id": "SRC-01", "event_id": "e1", "timestamp_unix_ms": 0,
          "address_family": "unix", "outcome": "success",
          "args": "verify-safe-to-apply --apply-all && rm -rf /"
        }]
    }"#;
    let benign = br#"{
        "schema_version": 1,
        "fixture_id": "benign",
        "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1,
        "coverage": "complete", "seen_events": 1, "dropped_events": 0,
        "events": [{
          "source_id": "SRC-01", "event_id": "e1", "timestamp_unix_ms": 0,
          "address_family": "unix", "outcome": "success", "args": "connect sock"
        }]
    }"#;
    let with_injection = recommend_bytes(injected, Capability::ExpectedRoot);
    let without = recommend_bytes(benign, Capability::ExpectedRoot);
    let a = serde_json::to_vec(&with_injection).expect("serializes");
    let b = serde_json::to_vec(&without).expect("serializes");
    assert_eq!(
        a, b,
        "injection-shaped args/fixture_id must never influence the recommendation"
    );
    assert_eq!(
        with_injection.recommended_families(),
        vec![sysdhardener_core::AddressFamily::Unix]
    );
    assert_eq!(with_injection.provisional(), ProvisionalStatus::Provisional);
}

#[test]
fn misleading_verified_safe_supported_language_is_never_emitted() {
    for (path, visibility) in [
        ("tests/fixtures/degraded.json", Capability::DegradedNonRoot),
        (
            "tests/fixtures/contradictory.json",
            Capability::DegradedNonRoot,
        ),
        ("tests/fixtures/with-loss.json", Capability::Unknown),
    ] {
        let finding = recommend(path, visibility);
        assert_eq!(finding.provisional(), ProvisionalStatus::Provisional);
        let json = serde_json::to_string(&finding).expect("finding serializes");
        for forbidden in [
            "\"verified\"",
            "\"safe\"",
            "\"supported\"",
            "\"complete\"",
            "auto-apply",
            "already-hardened",
        ] {
            assert!(
                !json.contains(forbidden),
                "finding for {path} must not contain {forbidden:?}: {json}"
            );
        }
        assert!(
            finding.compatibility_risk().unverified(),
            "canonical record risk must stay unverified for {path}"
        );
    }
}

#[test]
fn recommendation_is_deterministic_across_repeated_calls() {
    for path in [
        "tests/fixtures/happy.json",
        "tests/fixtures/contradictory.json",
        "tests/fixtures/with-loss.json",
    ] {
        let first = recommend(path, Capability::ExpectedRoot);
        let baseline = serde_json::to_vec(&first).expect("serializes");
        for _ in 0..100 {
            let again = recommend(path, Capability::ExpectedRoot);
            let bytes = serde_json::to_vec(&again).expect("serializes");
            assert_eq!(
                bytes, baseline,
                "repeat call on {path} must be byte-identical"
            );
        }
    }
}

#[test]
fn recommendation_is_total_over_all_valid_canonical_fixtures() {
    for path in [
        "tests/fixtures/happy.json",
        "tests/fixtures/degraded.json",
        "tests/fixtures/contradictory.json",
        "tests/fixtures/with-loss.json",
    ] {
        for visibility in [
            Capability::ExpectedRoot,
            Capability::DegradedNonRoot,
            Capability::Unknown,
        ] {
            let finding = recommend(path, visibility);
            assert_eq!(finding.provisional(), ProvisionalStatus::Provisional);
            assert!(
                !finding.contradiction_conditions().is_empty(),
                "{path} + {visibility:?} must carry contradiction conditions"
            );
        }
    }
}

#[test]
fn contradictory_netlink_observation_is_surfaced_never_silently_allowed() {
    let finding = recommend(
        "tests/fixtures/contradictory.json",
        Capability::ExpectedRoot,
    );
    let has_netlink_condition = finding.contradiction_conditions().iter().any(|c| {
        matches!(
            c,
            ContradictionCondition::ObservedWithoutSuccessfulUse {
                family: sysdhardener_core::AddressFamily::Netlink,
                ..
            }
        )
    });
    assert!(
        has_netlink_condition,
        "error-outcome netlink observation must surface as a contradiction condition"
    );
}

#[test]
fn capability_failures_do_not_contaminate_contradiction_conditions() {
    let events = vec![
        sysdhardener_core::ObservedEvent::new(
            sysdhardener_core::SourceId::from_static("SRC-01"),
            "e1".to_owned(),
            sysdhardener_core::FixtureTimestamp::from_raw_checked(0),
            sysdhardener_core::AddressFamily::Unix,
            sysdhardener_core::EventOutcome::Success,
            "connect".to_owned(),
        ),
        sysdhardener_core::ObservedEvent::new(
            sysdhardener_core::SourceId::from_static("SRC-13"),
            "e2".to_owned(),
            sysdhardener_core::FixtureTimestamp::from_raw_checked(1),
            sysdhardener_core::AddressFamily::Other("capability"),
            sysdhardener_core::EventOutcome::Error,
            "mount".to_owned(),
        ),
    ];
    let fixture = sysdhardener_core::Fixture::from_events(events.clone());
    let bundle = aggregate_address_family_evidence(&events, &fixture).expect("bundle");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("finding");

    for cond in finding.contradiction_conditions() {
        if let ContradictionCondition::ObservedWithoutSuccessfulUse { family, .. } = cond {
            assert!(
                !matches!(family, sysdhardener_core::AddressFamily::Other(_)),
                "capability or other-family errors must not contaminate address-family contradiction conditions, got: {family:?}"
            );
        }
    }
    for key in finding.aggregate_keys() {
        assert!(
            !key.contains("capability"),
            "aggregate_keys must not contain capability entries: {key}"
        );
    }
    for src in finding.source_ids() {
        assert_ne!(
            src, "SRC-13",
            "source_ids must not contain capability map sources"
        );
    }
}
