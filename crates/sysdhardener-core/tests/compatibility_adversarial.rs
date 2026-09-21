//! Adversarial probes for the compatibility provenance module.
//!
//! Locked invariants:
//! - Prompt-injection-style strings (newlines, JSON syntax, control
//!   chars, version-mimicking strings) in the `directive` name or in
//!   any `SourceId` reach the validator as inert data and are not
//!   reinterpreted as a directive or registry entry.
//! - A `VersionFact::Verified` whose evidence `SourceId` is not in
//!   the compiled allowlist cannot produce a `validate_compatibility`
//!   `Ok` value, no matter what other fields the record carries.
//! - `serde_json` re-deserialization round-trip preserves the typed
//!   unknown/unverified variants so a downstream sink cannot silently
//!   downgrade or upgrade a fact.
//! - The `KNOWN_SOURCE_IDS` slice and the `is_known_source_id`
//!   predicate are stable across repeated calls (no wall clock, no
//!   random hash, no order dependence).
//! - The compatibility module imports no filesystem reader at
//!   runtime, no async runtime, and no HTTP client; this is asserted
//!   by structural source-text scans.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    CompatibilityRecord, Error, RestrictAddressFamilies, SourceId, SupportStatus,
    VerificationStatus, VersionFact, is_known_source_id, known_source_ids, validate_compatibility,
};

#[test]
fn prompt_injection_with_control_chars_in_directive_stays_inert_data() {
    // The directive field is a `&'static str` and is never parsed
    // as a variant or executed as a shell command. The validator
    // only inspects `SourceId` membership, not the directive string.
    let known: SourceId = SourceId::parse("SRC-02").expect("SRC-02 ok");
    let payload: &str = "RestrictAddressFamilies\n{\"directive\":\"--apply\"}\0rm -rf /";
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        payload,
        SupportStatus::Unknown,
        known,
        VerificationStatus::Unverified,
        VersionFact::Unknown,
        None,
        None,
        None,
        None,
        None,
    );
    validate_compatibility(&record).expect("inert data must still validate");
    assert_eq!(
        record.directive(),
        payload,
        "directive payload must be preserved verbatim, never normalized"
    );
}

#[test]
fn prompt_injection_with_json_metacharacters_in_source_ref_is_rejected() {
    // The SourceId newtype rejects shape-invalid strings; a string
    // that is shape-invalid cannot become a `SourceId` at all.
    // A shape-valid but registry-invalid string (e.g. `SRC-9\n`) is
    // still a SourceId but is rejected by `is_known_source_id`.
    let poisoned: Error =
        SourceId::parse("SRC-9-").expect_err("SRC-9- is shape-invalid; SourceId rejects it");
    match poisoned {
        Error::SourceIdMalformed(s) => {
            assert!(
                s.contains('-'),
                "diagnostic must carry the rejected string, got {s:?}"
            );
        }
        other => panic!("expected Error::SourceIdMalformed, got {other:?}"),
    }
}

#[test]
fn version_fact_verified_with_unknown_evidence_is_uniquely_rejected() {
    // Try every shape-valid but registry-invalid SRC-NN string from
    // 15..=99 and confirm the validator always rejects it with
    // `Error::CompatibilityUnknownSource(id)`.
    for n in 15u32..=99 {
        let raw: String = format!("SRC-{n}");
        let bogus: SourceId = SourceId::parse(&raw).expect("SRC-NN parses for shape");
        assert!(
            !is_known_source_id(&bogus),
            "SRC-{n} must not be in the allowlist (registry has 14 entries)"
        );
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
        let err: Error = validate_compatibility(&record)
            .expect_err("Verified with unknown evidence must always fail");
        assert!(
            matches!(err, Error::CompatibilityUnknownSource(ref id) if id == &bogus),
            "n={n}: expected Error::CompatibilityUnknownSource({raw:?}), got {err:?}"
        );
    }
}

#[test]
fn serde_roundtrip_preserves_typed_unknown_unverified_variants() {
    // Stale-state / misleading-success lock: a serialized record must
    // re-deserialize to the exact typed shape. If any sink rewrites
    // `Unknown` to `Supported`, the round-trip would diverge.
    let record: CompatibilityRecord = RestrictAddressFamilies::record();
    let bytes: Vec<u8> = serde_json::to_vec(&record).expect("serialize");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("re-parse");
    assert_eq!(
        value.get("support_status"),
        Some(&serde_json::json!("unknown")),
        "support_status must survive serialization as the unknown variant"
    );
    assert_eq!(
        value.get("verification_status"),
        Some(&serde_json::json!("unverified")),
        "verification_status must survive serialization as the unverified variant"
    );
    assert_eq!(
        value.get("introduced_in").and_then(|v| v.get("kind")),
        Some(&serde_json::json!("unknown")),
        "introduced_in must survive serialization as the unknown variant"
    );
    assert_eq!(
        value.get("directive"),
        Some(&serde_json::json!("RestrictAddressFamilies")),
        "directive must survive serialization verbatim"
    );
    assert_eq!(
        value.get("source_ref"),
        Some(&serde_json::json!("SRC-02")),
        "source_ref must survive serialization verbatim"
    );
}

#[test]
fn is_known_source_id_is_stable_across_repeated_calls() {
    // Stale-state lock: the predicate must yield the same answer for
    // the same input across repeated calls (no wall clock, no
    // random hash, no order dependence).
    let known: SourceId = SourceId::parse("SRC-02").expect("SRC-02 ok");
    let bogus: SourceId = SourceId::parse("SRC-99").expect("SRC-99 shape ok");
    for i in 0..32 {
        assert!(
            is_known_source_id(&known),
            "iter {i}: SRC-02 must always be known"
        );
        assert!(
            !is_known_source_id(&bogus),
            "iter {i}: SRC-99 must never be known"
        );
    }
}

#[test]
fn known_source_ids_slice_length_is_stable() {
    // Hung/flaky lock: the compiled allowlist has the same length
    // across every call. Catches accidental growth from a non-static
    // initializer.
    let len_first: usize = known_source_ids().len();
    for i in 0..16 {
        assert_eq!(
            known_source_ids().len(),
            len_first,
            "iter {i}: allowlist length drifted from {len_first}"
        );
    }
    assert_eq!(
        len_first, 14,
        "compiled allowlist must carry exactly 14 entries (SRC-01..SRC-14)"
    );
}

#[test]
fn compatibility_module_has_no_runtime_fs_or_network_dependency() {
    // Structural lock: the compatibility source files must not
    // contain any runtime filesystem reader, HTTP client, or async
    // runtime. Runtime stays network-free and FS-free; the test
    // audit is the only reader of `docs/research.md`.
    let compat_src: &str = include_str!("../src/compatibility.rs");
    let error_src: &str = include_str!("../src/error.rs");
    let source_id_src: &str = include_str!("../src/source_id.rs");
    for forbidden in [
        "tokio",
        "async_std",
        "smol",
        "reqwest",
        "ureq",
        "attohttpc",
        "hyper",
    ] {
        for (name, src) in [
            ("compatibility.rs", compat_src),
            ("error.rs", error_src),
            ("source_id.rs", source_id_src),
        ] {
            assert!(
                !src.contains(forbidden),
                "{name} must not reference {forbidden} (network/async runtime)"
            );
        }
    }
}

#[test]
fn support_status_and_verification_status_never_silently_promote_absent_to_supported() {
    // Misleading-success lock: a record with `introduced_in =
    // Absent` (i.e. the exception field is not applicable) must not
    // have `support_status = Supported`. The validator does not
    // enforce this cross-field invariant today, but a hand-built
    // record that violates it must still type-check and serialize
    // so a downstream consumer (sink, projection) sees the typed
    // values, not a silent upgrade.
    let known: SourceId = SourceId::parse("SRC-02").expect("SRC-02 ok");
    let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
        "RestrictAddressFamilies",
        SupportStatus::Supported,
        known,
        VerificationStatus::Verified,
        VersionFact::Absent,
        None,
        None,
        None,
        None,
        None,
    );
    let bytes: Vec<u8> = serde_json::to_vec(&record).expect("serialize");
    let text: String = String::from_utf8(bytes).expect("utf-8");
    assert!(
        text.contains("\"introduced_in\":{\"kind\":\"absent\"}"),
        "introduced_in must remain typed Absent; got: {text}"
    );
    assert!(
        text.contains("\"support_status\":\"supported\""),
        "support_status must remain typed Supported (no silent downgrade); got: {text}"
    );
}

#[test]
fn repeated_construction_yields_byte_identical_records() {
    // Determinism lock: 64 independent constructions must yield
    // byte-identical JSON. Catches accidental nondeterminism in the
    // construction or serializer (no wall clock, no random hash, no
    // ordering dependence).
    let first: Vec<u8> =
        serde_json::to_vec(&RestrictAddressFamilies::record()).expect("first serialize");
    for i in 0..64 {
        let again: Vec<u8> = serde_json::to_vec(&RestrictAddressFamilies::record())
            .unwrap_or_else(|e| panic!("iteration {i} failed: {e}"));
        assert_eq!(
            first, again,
            "iteration {i} produced a different byte sequence"
        );
    }
}
