//! Happy-path contract tests for the minimal-plus-exceptions
//! compatibility provenance record.
//!
//! Locked invariants:
//! - The canonical `RestrictAddressFamilies=` record resolves to a
//!   `SourceId` that is present in the compiled registry allowlist
//!   (validated at test time against the live `source-registry.md`).
//! - The record is serializable, byte-stable across repeated calls, and
//!   carries unknown/unverified version-sensitive fields for every fact
//!   the project has not yet verified.
//! - The record carries its `directive`, `support_status`,
//!   `verification_status`, and conditional exception fields as typed
//!   variants (no bare strings in the typed interior).
//!
//! Adversarial probes are split out into `compatibility_rejections.rs`
//! and `compatibility_provenance.rs` to keep each file under the
//! 250 pure-LOC ceiling.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::collections::BTreeSet;

use sysdhardener_core::{
    CompatibilityRecord, RestrictAddressFamilies, SourceId, SupportStatus, VerificationStatus,
    VersionFact, is_known_source_id, known_source_ids,
};

#[test]
fn restrict_address_families_directive_name_is_stable() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    assert_eq!(
        record.directive(),
        "RestrictAddressFamilies",
        "directive name must be the canonical systemd spelling"
    );
}

#[test]
fn restrict_address_families_source_ref_is_a_known_registry_id() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    let source_ref: &SourceId = record.source_ref();
    assert!(
        is_known_source_id(source_ref),
        "restrict_address_families source_ref={source_ref:?} must be in the compiled registry allowlist",
    );
}

#[test]
fn restrict_address_families_support_status_is_unknown_not_fabricated() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    assert_eq!(
        record.support_status(),
        SupportStatus::Unknown,
        "systemd version is unverified, so support_status must be Unknown rather than a fabricated 'supported'"
    );
}

#[test]
fn restrict_address_families_verification_status_is_unverified() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    assert_eq!(
        record.verification_status(),
        VerificationStatus::Unverified,
        "the baseline is not verified, so verification_status must be Unverified"
    );
}

#[test]
fn restrict_address_families_introduced_in_carries_version_fact_unknown() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    assert_eq!(
        record.introduced_in(),
        &VersionFact::Unknown,
        "introduced_in must be VersionFact::Unknown because systemd version is unverified"
    );
}

#[test]
fn restrict_address_families_carries_no_conditional_exception_fields() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    assert!(
        record.changed_in().is_none(),
        "RestrictAddressFamilies has no changed_in fact in the minimal record"
    );
    assert!(
        record.deprecated_in().is_none(),
        "RestrictAddressFamilies has no deprecated_in fact in the minimal record"
    );
    assert!(
        record.removed_in().is_none(),
        "RestrictAddressFamilies has no removed_in fact in the minimal record"
    );
    assert!(
        record.superseded_by().is_none(),
        "RestrictAddressFamilies has no superseded_by in the minimal record"
    );
    assert!(
        record.kernel_dependency().is_none(),
        "RestrictAddressFamilies has no kernel_dependency in the minimal record"
    );
}

#[test]
fn restrict_address_families_serializes_to_valid_json() {
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    let bytes: Vec<u8> = serde_json::to_vec(&record).expect("compatibility record must serialize");
    let text: &str = std::str::from_utf8(&bytes).expect("compatibility JSON must be utf-8");
    assert!(
        text.contains("\"directive\":\"RestrictAddressFamilies\""),
        "JSON must carry the directive name, got: {text}"
    );
    assert!(
        text.contains("\"source_ref\":"),
        "JSON must carry the source_ref field, got: {text}"
    );
    assert!(
        text.contains("\"verification_status\":\"unverified\""),
        "verification_status must serialize as the unverified variant, got: {text}"
    );
    assert!(
        text.contains("\"support_status\":\"unknown\""),
        "support_status must serialize as the unknown variant, got: {text}"
    );
    assert!(
        text.contains("\"introduced_in\":{\"kind\":\"unknown\"}"),
        "introduced_in must serialize as the unknown VersionFact variant, got: {text}"
    );
}

#[test]
fn restrict_address_families_serialized_output_is_byte_stable_across_repeated_calls() {
    // Stale-state lock: serialize the canonical record 16 times and
    // assert every byte sequence is identical. Catches accidental
    // non-determinism (random hash, wall clock, ordering) in the
    // compatibility serializer.
    let first: Vec<u8> =
        serde_json::to_vec(&RestrictAddressFamilies::record()).expect("first serialize ok");
    for i in 0..16 {
        let again: Vec<u8> = serde_json::to_vec(&RestrictAddressFamilies::record())
            .unwrap_or_else(|e| panic!("iteration {i} failed: {e}"));
        assert_eq!(
            first, again,
            "iteration {i} produced a different byte sequence"
        );
    }
}

#[test]
fn known_source_ids_allowlist_matches_markdown_registry() {
    // Stale-state lock: parse the live Markdown source registry, extract
    // every `SRC-NN` ID it advertises, and assert the compiled
    // allowlist contains exactly that set (and nothing else). This is
    // the audit hook: if the registry grows a new ID without updating
    // the allowlist, or the allowlist grows an ID without the
    // registry backing it, this test fails.
    let registry_path: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/research.md");
    let body: String = std::fs::read_to_string(registry_path)
        .unwrap_or_else(|e| panic!("must be able to read {registry_path} at audit time: {e}"));
    let mut from_markdown: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("| SRC-") {
            continue;
        }
        let id: &str = trimmed.split('|').nth(1).unwrap_or("").trim();
        if id.starts_with("SRC-") && id.len() > "SRC-".len() {
            from_markdown.insert(id.to_owned());
        }
    }
    assert!(
        !from_markdown.is_empty(),
        "no SRC-NN IDs could be parsed from {registry_path}; the audit is meaningless"
    );

    let compiled: BTreeSet<String> = known_source_ids()
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();

    assert_eq!(
        compiled, from_markdown,
        "compiled allowlist must match the live source-registry.md exactly"
    );
}

#[test]
fn every_known_source_id_parses_as_a_well_formed_source_id() {
    // Stale-state lock: every compiled allowlist entry must itself
    // round-trip through `SourceId::parse`. Catches a typo'd literal
    // in the allowlist that would silently pass `is_known_source_id`
    // while still failing the typed boundary.
    for id in known_source_ids() {
        let raw: &str = id.as_str();
        let parsed: SourceId = SourceId::parse(raw).unwrap_or_else(|e| {
            panic!("compiled allowlist entry {raw:?} failed SourceId::parse: {e}")
        });
        assert_eq!(
            parsed.as_str(),
            raw,
            "parsed value must equal raw for {raw:?}"
        );
        assert!(
            is_known_source_id(&parsed),
            "compiled allowlist entry {raw:?} must register as known via is_known_source_id"
        );
    }
}
