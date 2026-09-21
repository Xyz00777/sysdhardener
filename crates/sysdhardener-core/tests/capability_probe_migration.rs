//! Migration + compile-time/type tests for the capability→coverage
//! refactor.
//!
//! Two contracts are locked here:
//!
//! 1. **Wire contract unchanged**: fixture envelopes carrying
//!    `coverage: "complete"` still parse to
//!    `CoverageQuality::Complete` exactly as before the refactor.
//!    Completeness originates exclusively in the fixture wire — the
//!    capability probe refactor never silently alters fixture
//!    semantics.
//! 2. **Capability can never imply completeness**: the const blocks
//!    below are evaluated at *compile time*; if the mapping ever
//!    yields `CoverageQuality::Complete` from a capability alone,
//!    this test file fails to compile.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic and compile-time assertions on the capability contract"
)]

use sysdhardener_core::{Capability, CoverageQuality, combine_visibility, parse_fixture_v1};

const _: () = {
    assert!(
        !matches!(
            CoverageQuality::from_capability(Capability::ExpectedRoot),
            CoverageQuality::Complete
        ),
        "ExpectedRoot must never imply complete coverage"
    );
    assert!(
        !matches!(
            CoverageQuality::from_capability(Capability::DegradedNonRoot),
            CoverageQuality::Complete
        ),
        "DegradedNonRoot must never imply complete coverage"
    );
    assert!(
        !matches!(
            CoverageQuality::from_capability(Capability::Unknown),
            CoverageQuality::Complete
        ),
        "Unknown capability must never imply complete coverage"
    );
};

#[test]
fn fixture_wire_complete_tag_still_parses_to_complete() {
    let fixture_json: &str = r#"{
        "schema_version": 1,
        "fixture_id": "migration-check",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;
    let fixture = parse_fixture_v1(fixture_json.as_bytes()).expect("complete-tag fixture parses");
    assert_eq!(fixture.coverage(), CoverageQuality::Complete);
}

#[test]
fn fixture_wire_degraded_and_unknown_tags_still_parse() {
    for (tag, expected) in [
        ("degraded", CoverageQuality::Degraded),
        ("unknown", CoverageQuality::Unknown),
    ] {
        let fixture_json: String = format!(
            r#"{{
                "schema_version": 1,
                "fixture_id": "migration-check-{tag}",
                "first_timestamp_unix_ms": 0,
                "last_timestamp_unix_ms": 0,
                "coverage": "{tag}",
                "seen_events": 0,
                "dropped_events": 0,
                "events": []
            }}"#
        );
        let fixture = parse_fixture_v1(fixture_json.as_bytes()).expect("wire coverage tag parses");
        assert_eq!(fixture.coverage(), expected);
    }
}

#[test]
fn complete_is_reachable_only_via_evidence_not_capability() {
    // Root + unknown evidence stays Unknown: root alone cannot
    // construct Complete.
    assert_eq!(
        combine_visibility(Capability::ExpectedRoot, CoverageQuality::Unknown),
        CoverageQuality::Unknown
    );
    // Complete survives only when the *evidence* carried it and the
    // capability is ExpectedRoot; the refactor preserved fixture
    // semantics instead of silently degrading old fixtures.
    assert_eq!(
        combine_visibility(Capability::ExpectedRoot, CoverageQuality::Complete),
        CoverageQuality::Complete
    );
}

#[test]
fn nonroot_and_unknown_capability_degrade_evidence_complete() {
    for cap in [Capability::DegradedNonRoot, Capability::Unknown] {
        assert_eq!(
            combine_visibility(cap, CoverageQuality::Complete),
            CoverageQuality::Degraded,
            "{cap:?} must degrade evidence-complete"
        );
    }
}
