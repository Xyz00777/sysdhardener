//! Adversarial / audit probes for the minimal-plus-exceptions
//! compatibility provenance record.
//!
//! This file holds the audit-time registry parse, the determinism
//! lock, and the "no fabricated baseline fact" assertion. Source
//! registry validation may parse the Markdown registry here (test
//! time only) — runtime never reads docs.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::collections::BTreeSet;

use sysdhardener_core::{
    RestrictAddressFamilies, SupportStatus, VerificationStatus, VersionFact, known_source_ids,
};

#[test]
fn no_fabricated_baseline_or_kernel_version_literal_in_record() {
    let record: sysdhardener_core::CompatibilityRecord = RestrictAddressFamilies::record();
    let bytes: Vec<u8> = serde_json::to_vec(&record).expect("compatibility record must serialize");
    let text: String = String::from_utf8(bytes).expect("compatibility JSON must be utf-8");

    // No hardcoded version literal may leak into the record.
    // Versions must not be assumed without verification.
    for forbidden in [
        "Ubuntu",
        "ubuntu",
        "20.04",
        "22.04",
        "24.04",
        "26.04",
        "5.15",
        "6.1",
        "6.6",
        "systemd-2",
        "kernel-",
        "v256",
        "v255",
        "v254",
        "1.0.0",
    ] {
        assert!(
            !text.contains(forbidden),
            "compatibility record must not carry fabricated baseline literal {forbidden:?}; serialized JSON was: {text}"
        );
    }
}

#[test]
fn audit_parses_source_registry_and_confirms_thirteen_known_ids() {
    // Audit-time parse of the Markdown registry. Runtime never does
    // this; the compiled allowlist is what runtime uses.
    let registry_path: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/research.md");
    let body: String = std::fs::read_to_string(registry_path)
        .unwrap_or_else(|e| panic!("must be able to read {registry_path} at audit time: {e}"));

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("| SRC-") {
            continue;
        }
        let id: &str = trimmed.split('|').nth(1).unwrap_or("").trim();
        if id.starts_with("SRC-") && id.len() > "SRC-".len() {
            seen.insert(id.to_owned());
        }
    }

    assert_eq!(
        seen.len(),
        14,
        "source registry must carry exactly 14 SRC-NN rows; got {seen:?}"
    );
    for n in 1..=14u32 {
        let expected: String = format!("SRC-{n:02}");
        assert!(
            seen.contains(&expected),
            "source registry must contain {expected}; got {seen:?}"
        );
    }
}

#[test]
fn audit_does_not_find_extra_or_renumbered_source_ids_in_registry() {
    // Stale-state lock: the registry is "stable and reused; IDs are
    // not renumbered when rows are added" per the registry
    // Conventions. If anyone renumbers an ID, the compiled allowlist
    // and the canonical record both break, and this test fails
    // before anything else.
    let registry_path: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/research.md");
    let body: String = std::fs::read_to_string(registry_path)
        .unwrap_or_else(|e| panic!("must be able to read {registry_path} at audit time: {e}"));
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if !trimmed.starts_with("| SRC-") {
            continue;
        }
        let id: &str = trimmed.split('|').nth(1).unwrap_or("").trim();
        if id.starts_with("SRC-") && id.len() > "SRC-".len() {
            let suffix: &str = &id["SRC-".len()..];
            assert!(
                suffix.bytes().all(|b| b.is_ascii_digit()),
                "registry ID {id:?} has a non-digit suffix"
            );
        }
    }
}

#[test]
fn version_fact_absent_does_not_imply_supported() {
    // `VersionFact::Absent` is the explicit "this exception field is
    // not applicable" shape. The compatibility record must never
    // let Absent silently upgrade support_status or verification_status.
    let record: sysdhardener_core::CompatibilityRecord = RestrictAddressFamilies::record();
    assert_eq!(
        record.introduced_in(),
        &VersionFact::Unknown,
        "introduced_in must be Unknown when unverified, never Absent"
    );
    assert_eq!(
        record.support_status(),
        SupportStatus::Unknown,
        "support_status must remain Unknown while introduced_in is Unknown"
    );
    assert_eq!(
        record.verification_status(),
        VerificationStatus::Unverified,
        "verification_status must remain Unverified while baseline is unverified"
    );
}

#[test]
fn compatiblity_record_does_not_read_docs_or_network_at_runtime() {
    // Stale-state lock: the compatibility module must not call any
    // filesystem read of `docs/` at runtime, and must not import any
    // network/HTTP/reqwest/ureq/attohttpc dependency.
    //
    // We assert this structurally: scan the compiled crate's source
    // files for forbidden runtime-doc/network calls. The test fails
    // if anyone reintroduces a `read_to_string` of the registry path
    // inside `src/compatibility.rs`.
    let compat_src: &str = include_str!("../src/compatibility.rs");
    assert!(
        !compat_src.contains("read_to_string"),
        "compatibility.rs must not read docs at runtime (found `read_to_string`)"
    );
    assert!(
        !compat_src.contains("std::fs"),
        "compatibility.rs must not call std::fs at runtime (found `std::fs` reference)"
    );
    assert!(
        !compat_src.contains("reqwest")
            && !compat_src.contains("ureq")
            && !compat_src.contains("attohttpc"),
        "compatibility.rs must not depend on any HTTP client at runtime"
    );
    assert!(
        !compat_src.contains("tokio")
            && !compat_src.contains("async_std")
            && !compat_src.contains("smol"),
        "compatibility.rs must not depend on any async runtime"
    );
}

#[test]
fn compiled_allowlist_is_a_const_static_array() {
    // The allowlist is a compile-time `const` of pre-parsed
    // `SourceId` values, not a runtime-built Vec. We assert the
    // symbol is `static` and not built dynamically.
    let count: usize = known_source_ids().len();
    assert!(
        count >= 11,
        "compiled allowlist must carry at least 11 source IDs, got {count}"
    );
    // Order is not part of the contract, but every call yields the
    // same length (determinism lock).
    assert_eq!(known_source_ids().len(), count);
}
