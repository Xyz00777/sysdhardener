//! Rejection contract tests for the single provisional
//! `RestrictAddressFamilies=` recommendation.
//!
//! Locked invariants:
//! - the recommendation function validates the compatibility record and
//!   rejects an unknown `source_ref` with the typed
//!   `Error::CompatibilityUnknownSource` discriminant (linkage
//!   integrity is never bypassed);
//! - a `Verified` version fact without a known evidence source is
//!   rejected;
//! - a `Supported` claim without `Verified` verification still yields an
//!   unverified compatibility risk: the candidate never claims safe or
//!   supported language that the typed evidence does not back.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::fs;

use sysdhardener_core::{
    AddressFamily, Capability, CompatibilityRecord, Error, RestrictAddressFamilies, SourceId,
    SupportStatus, VerificationStatus, VersionFact, aggregate_address_family_evidence,
    parse_fixture_v1, recommend_restrict_address_families,
};

fn canonical_bundle() -> sysdhardener_core::AddressFamilyBundle {
    let bytes = fs::read("tests/fixtures/happy.json").expect("happy fixture must be readable");
    let parsed = parse_fixture_v1(&bytes).expect("happy fixture must parse");
    aggregate_address_family_evidence(parsed.events(), &parsed).expect("must aggregate")
}

#[test]
fn recommendation_rejects_record_with_unknown_source_ref() {
    let bogus: SourceId = SourceId::parse("SRC-99").expect("SRC-99 shape ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        SupportStatus::Unknown,
        bogus.clone(),
        VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        None,
    );
    let bundle = canonical_bundle();
    let err: Error =
        recommend_restrict_address_families(&bundle, Capability::ExpectedRoot, &record)
            .expect_err("unknown source_ref must be rejected");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource({bogus:?}), got {err:?}"
    );
}

#[test]
fn recommendation_rejects_verified_fact_with_unknown_evidence_source() {
    let bogus: SourceId = SourceId::parse("SRC-77").expect("SRC-77 shape ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        SupportStatus::Supported,
        SourceId::parse("SRC-02").expect("SRC-02 ok"),
        VerificationStatus::Verified,
        VersionFact::Verified {
            source_ref: bogus.clone(),
        },
        None,
        None,
        None,
        None,
        None,
    );
    let bundle = canonical_bundle();
    let err: Error =
        recommend_restrict_address_families(&bundle, Capability::ExpectedRoot, &record)
            .expect_err("Verified with unknown evidence must be rejected");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource, got {err:?}"
    );
}

#[test]
fn supported_claim_without_verified_verification_still_yields_unverified_risk() {
    // SupportStatus::Supported without VerificationStatus::Verified is
    // not a backed claim; the compatibility risk must stay unverified.
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        SupportStatus::Supported,
        SourceId::parse("SRC-02").expect("SRC-02 ok"),
        VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        None,
    );
    let bundle = canonical_bundle();
    let finding = recommend_restrict_address_families(&bundle, Capability::ExpectedRoot, &record)
        .expect("known source_ref must recommend");
    assert!(
        finding.compatibility_risk().unverified(),
        "unverified verification must keep the risk unverified"
    );
    let json = serde_json::to_string(finding.compatibility_risk()).expect("risk serializes");
    assert!(
        json.contains("\"support\":\"supported\"")
            && json.contains("\"verification\":\"unverified\""),
        "the risk must carry the record's typed facts verbatim: {json}"
    );
    assert!(
        !json.contains("\"verification\":\"verified\""),
        "the risk label must not claim verified verification: {json}"
    );
}

#[test]
fn recommendation_accepts_the_canonical_record() {
    let bundle = canonical_bundle();
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("canonical record must recommend");
    assert_eq!(finding.recommended_families().len(), 3);
    assert!(
        finding
            .recommended_families()
            .contains(&AddressFamily::Inet6),
        "canonical happy fixture recommends inet6"
    );
}
