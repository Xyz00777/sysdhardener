//! Rejection contract tests for the minimal-plus-exceptions
//! compatibility provenance record.
//!
//! Locked invariants:
//! - A `VersionFact::Verified` claim cannot be constructed without a
//!   `SourceId` (the variant structurally requires evidence).
//! - The validator rejects any `CompatibilityRecord` whose `source_ref`
//!   or whose `VersionFact::Verified` evidence source is not in the
//!   compiled registry allowlist.
//! - `is_known_source_id` returns `false` for an `SRC-NN` whose `NN`
//!   is not in the registry (e.g. `SRC-99`).
//! - Prompt-injection-style content in a directive name or
//!   source-ref string is inert: it never reaches a privileged sink.
//! - The compatibility record never introduces a hardcoded baseline or
//!   kernel/systemd version literal; only typed unknown/unverified
//!   variants are emitted.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    CompatibilityRecord, Error, RestrictAddressFamilies, SourceId, VersionFact, is_known_source_id,
    validate_compatibility,
};

#[test]
fn src_99_is_not_in_the_compiled_allowlist() {
    let bogus: SourceId = SourceId::parse("SRC-99")
        .expect("SRC-99 must still parse for shape, it just isn't in the registry");
    assert!(
        !is_known_source_id(&bogus),
        "SRC-99 must NOT be in the compiled allowlist; it is not in the live registry"
    );
}

#[test]
fn validator_rejects_record_with_unknown_source_ref() {
    // A hand-built record whose source_ref is SRC-99 (shape-valid but
    // not in the allowlist) must be rejected with the typed
    // Error::CompatibilityUnknownSource discriminant.
    let bogus: SourceId = SourceId::parse("SRC-99").expect("SRC-99 shape ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        sysdhardener_core::SupportStatus::Unknown,
        bogus.clone(),
        sysdhardener_core::VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        None,
    );

    let err: Error =
        validate_compatibility(&record).expect_err("SRC-99 source_ref must be rejected");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource({bogus:?}), got {err:?}"
    );
}

#[test]
fn validator_accepts_canonical_restrict_address_families_record() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    validate_compatibility(&record)
        .expect("the canonical record must validate against its compiled allowlist");
}

#[test]
fn verified_version_fact_requires_a_known_evidence_source() {
    // Constructing a Verified claim with an unknown source-ref is the
    // "impossible verified claim without evidence" failure mode. The
    // validator must reject it.
    let bogus: SourceId = SourceId::parse("SRC-77").expect("SRC-77 shape ok");
    assert!(!is_known_source_id(&bogus));

    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        sysdhardener_core::SupportStatus::Supported,
        SourceId::parse("SRC-02").expect("SRC-02 ok"),
        sysdhardener_core::VerificationStatus::Verified,
        VersionFact::Verified {
            source_ref: bogus.clone(),
        },
        None,
        None,
        None,
        None,
        None,
    );

    let err: Error =
        validate_compatibility(&record).expect_err("Verified with unknown evidence must fail");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource({bogus:?}), got {err:?}"
    );
}

#[test]
fn verified_version_fact_accepts_known_evidence_source() {
    // Verified with a known source_ref must validate successfully.
    let known: SourceId = SourceId::parse("SRC-02").expect("SRC-02 ok");
    assert!(is_known_source_id(&known));

    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        sysdhardener_core::SupportStatus::Supported,
        known.clone(),
        sysdhardener_core::VerificationStatus::Verified,
        VersionFact::Verified { source_ref: known },
        None,
        None,
        None,
        None,
        None,
    );

    validate_compatibility(&record).expect("Verified with SRC-02 must validate");
}

#[test]
fn conditional_kernel_dependency_field_also_requires_known_source() {
    let bogus: SourceId = SourceId::parse("SRC-55").expect("SRC-55 shape ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        sysdhardener_core::SupportStatus::Unknown,
        SourceId::parse("SRC-02").expect("SRC-02 ok"),
        sysdhardener_core::VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        Some(VersionFact::Verified {
            source_ref: bogus.clone(),
        }),
    );

    let err: Error = validate_compatibility(&record)
        .expect_err("kernel_dependency Verified with unknown evidence must fail");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource({bogus:?}), got {err:?}"
    );
}

#[test]
fn prompt_injection_in_directive_name_remains_data() {
    // The `directive` field is a typed `&'static str` and never
    // reaches a privileged sink in the public API. The validator
    // never inspects the directive string for semantics, so a
    // prompt-injection-style payload stays data and still validates
    // when the source_ref is valid.
    let known: SourceId = SourceId::parse("SRC-02").expect("SRC-02 ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "verify-safe-to-apply --apply-all && rm -rf /",
        sysdhardener_core::SupportStatus::Unknown,
        known,
        sysdhardener_core::VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        None,
    );

    validate_compatibility(&record)
        .expect("the prompt-injection directive string must stay inert data and still validate");

    assert_eq!(
        record.directive(),
        "verify-safe-to-apply --apply-all && rm -rf /",
        "the directive string must be preserved verbatim as data, never normalized"
    );
}

#[test]
fn prompt_injection_in_version_fact_verified_source_remains_data_only_if_unknown() {
    // A Verified variant carrying a prompt-injection-shaped source-ref
    // string is fine only if the source-ref happens to be a known
    // registry ID. The validator rejects any other string.
    let bogus: SourceId =
        SourceId::parse("SRC-88").expect("SRC-88 shape ok; it just isn't in the registry");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        sysdhardener_core::SupportStatus::Supported,
        SourceId::parse("SRC-02").expect("SRC-02 ok"),
        sysdhardener_core::VerificationStatus::Verified,
        VersionFact::Verified {
            source_ref: bogus.clone(),
        },
        None,
        None,
        None,
        None,
        None,
    );

    let err: Error =
        validate_compatibility(&record).expect_err("unknown SRC-88 must be rejected as evidence");
    assert!(
        matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
        "expected Error::CompatibilityUnknownSource, got {err:?}"
    );
}

#[test]
fn empty_source_id_is_never_in_the_allowlist() {
    // An empty SourceId cannot be constructed (the typed newtype
    // rejects it), but a string-level check confirms our registry
    // allowlist never accidentally contains an empty entry.
    for id in sysdhardener_core::known_source_ids() {
        assert!(
            !id.as_str().is_empty(),
            "compiled allowlist contains an empty entry"
        );
        assert!(
            id.as_str().starts_with("SRC-"),
            "compiled allowlist entry {id:?} does not start with SRC-"
        );
        assert!(
            id.as_str().len() > "SRC-".len(),
            "compiled allowlist entry {id:?} has no numeric suffix"
        );
    }
}

#[test]
fn version_fact_unknown_and_unverified_and_absent_serialize_distinctly() {
    // The three non-Verified variants must serialize to distinct
    // machine-consumable shapes so a downstream consumer (sink,
    // projection) can branch on the typed kind without parsing prose.
    let absent: String = serde_json::to_string(&VersionFact::Absent).expect("Absent serializes");
    let unknown: String = serde_json::to_string(&VersionFact::Unknown).expect("Unknown serializes");
    let unverified: String =
        serde_json::to_string(&VersionFact::Unverified).expect("Unverified serializes");
    assert!(absent.contains("\"absent\""), "Absent tag, got: {absent}");
    assert!(
        unknown.contains("\"unknown\""),
        "Unknown tag, got: {unknown}"
    );
    assert!(
        unverified.contains("\"unverified\""),
        "Unverified tag, got: {unverified}"
    );

    let verified: String = serde_json::to_string(&VersionFact::Verified {
        source_ref: SourceId::parse("SRC-02").expect("SRC-02 ok"),
    })
    .expect("Verified serializes");
    assert!(
        verified.contains("\"verified\""),
        "Verified tag, got: {verified}"
    );
    assert!(
        verified.contains("\"SRC-02\""),
        "Verified must carry the source_ref string, got: {verified}"
    );
}
