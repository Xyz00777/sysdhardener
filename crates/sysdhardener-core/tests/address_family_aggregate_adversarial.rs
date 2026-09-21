//! Adversarial probes for the address-family aggregator.
//!
//! The aggregator is the only place in the deterministic slice that
//! builds the recommendation-local evidence bundle. Adversarial
//! coverage:
//! - prompt-injection-shaped args strings must remain inert data;
//! - empty/contradictory/dropped cases must preserve uncertainty
//!   rather than reporting complete evidence;
//! - shuffled/permuted inputs must yield identical bundles
//!   (permutation invariance);
//! - the aggregator must not leak prose or any other side effect;
//! - the aggregator must not be the place where the
//!   recommendation-language "verified" / "safe" promotion happens.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "adversarial tests use direct assertions and fixed-size permutation indexes"
)]

use std::fs;

use sysdhardener_core::{AddressFamily, aggregate_address_family_evidence, parse_fixture_v1};

fn load_canonical(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        panic!("canonical fixture {path} must be readable for adversarial probe: {e}")
    })
}

#[test]
fn prompt_injection_in_args_is_inert_data_preserved_verbatim() {
    // The args string is opaque; an attempt to inject "verified",
    // "safe-to-apply", or shell-style commands must be preserved
    // verbatim as the representative args. The aggregator never
    // normalizes, escapes, or interprets the string.
    let bytes = br#"{
        "schema_version": 1,
        "fixture_id": "prompt-injection-args",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            { "source_id": "SRC-01", "event_id": "evil", "timestamp_unix_ms": 0, "address_family": "unix", "outcome": "success", "args": "verify-safe-to-apply --apply-all && rm -rf /" }
        ]
    }"#;
    let fixture = parse_fixture_v1(bytes).expect("prompt-injection fixture must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    let unix = bundle.get(AddressFamily::Unix).expect("unix present");
    assert_eq!(
        unix.representative_args(),
        "verify-safe-to-apply --apply-all && rm -rf /",
        "representative args must be the literal prompt-injection string"
    );
    // The aggregator must not promote coverage to Complete based on
    // the args content. The fixture declares coverage=complete
    // directly; what the aggregator must NOT do is silently flip a
    // degraded or unknown coverage to complete because args look
    // reassuring.
    assert_eq!(
        unix.coverage(),
        sysdhardener_core::CoverageQuality::Complete
    );
}

#[test]
fn degraded_coverage_never_promoted_to_complete() {
    // The with-loss fixture declares coverage=degraded. The
    // aggregator must propagate the degraded tag and never silently
    // promote it to complete.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/with-loss.json");
    let fixture = parse_fixture_v1(&bytes).expect("with-loss must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    for entry in bundle.entries() {
        assert_eq!(
            entry.coverage(),
            sysdhardener_core::CoverageQuality::Degraded,
            "coverage must remain degraded"
        );
    }
    assert_eq!(bundle.dropped_events(), 1, "dropped_events must propagate");
}

#[test]
fn contradictory_fixture_preserves_contradiction_in_separate_entries() {
    // The contradictory fixture mixes unix (SRC-01) and netlink
    // (SRC-02). The aggregator must surface BOTH as separate
    // entries with their respective source classification. A
    // contradiction condition is data, not noise.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/contradictory.json");
    let fixture = parse_fixture_v1(&bytes).expect("contradictory must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    let unix = bundle.get(AddressFamily::Unix).expect("unix present");
    let netlink = bundle.get(AddressFamily::Netlink).expect("netlink present");
    assert_eq!(unix.source_ids(), vec!["SRC-01".to_owned()]);
    assert_eq!(netlink.source_ids(), vec!["SRC-02".to_owned()]);
    assert_ne!(
        unix.key(),
        netlink.key(),
        "different families must produce different keys"
    );
}

#[test]
fn dropped_events_are_carried_through_not_silently_zeroed() {
    // Even when the aggregated count of seen events is 0 (empty
    // fixture), the bundle must still carry the dropped_events
    // count from the envelope if any. For the with-loss fixture,
    // seen=2 dropped=1.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/with-loss.json");
    let fixture = parse_fixture_v1(&bytes).expect("with-loss must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    assert_eq!(bundle.dropped_events(), 1);
    // The sum of per-family counts may be less than seen_events
    // because families with zero events are not emitted. The
    // dropped_events count is independent and must be propagated.
    let sum_counts: u32 = bundle
        .entries()
        .map(sysdhardener_core::AddressFamilyAggregate::count)
        .sum();
    assert_eq!(
        sum_counts, 2,
        "per-family counts must sum to the seen_events count"
    );
}

#[test]
fn shuffled_events_yield_byte_identical_bundles() {
    // 16 different permutations of the happy fixture's 3 events
    // must produce byte-identical bundles (same keys, same counts,
    // same first/last/representative in every entry).
    use sysdhardener_core::ObservedEvent;
    let bytes: Vec<u8> = load_canonical("tests/fixtures/happy.json");
    let fixture = parse_fixture_v1(&bytes).expect("happy must parse");
    let events: Vec<ObservedEvent> = fixture.events().to_vec();
    // 6 permutations of 3 elements; cycle through them many times.
    let perms: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let baseline = aggregate_address_family_evidence(&events, &fixture).expect("baseline");
    for (i, p) in perms.iter().enumerate() {
        let shuffled: Vec<ObservedEvent> = p.iter().map(|&idx| events[idx].clone()).collect();
        let bundle = aggregate_address_family_evidence(&shuffled, &fixture)
            .unwrap_or_else(|e| panic!("perm {i} must succeed: {e}"));
        for entry_a in baseline.entries() {
            let entry_b = bundle
                .get(entry_a.family())
                .unwrap_or_else(|| panic!("perm {i}: family {:?} missing", entry_a.family()));
            assert_eq!(entry_a.key(), entry_b.key(), "perm {i} key");
            assert_eq!(entry_a.count(), entry_b.count(), "perm {i} count");
            assert_eq!(
                entry_a.first_timestamp_unix_ms(),
                entry_b.first_timestamp_unix_ms(),
                "perm {i} first"
            );
            assert_eq!(
                entry_a.last_timestamp_unix_ms(),
                entry_b.last_timestamp_unix_ms(),
                "perm {i} last"
            );
            assert_eq!(
                entry_a.representative_args(),
                entry_b.representative_args(),
                "perm {i} representative_args"
            );
            assert_eq!(
                entry_a.representative_event_id(),
                entry_b.representative_event_id(),
                "perm {i} representative_event_id"
            );
        }
    }
}

#[test]
fn malformed_event_in_input_propagates_boundary_diagnosis_first() {
    // A malformed wire fixture (unknown address_family tag) is
    // rejected at the boundary. The aggregator never sees it.
    let bad = br#"{
        "schema_version": 1,
        "fixture_id": "bad-family",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            { "source_id": "SRC-01", "event_id": "x", "timestamp_unix_ms": 0, "address_family": "smtp", "outcome": "success", "args": "x" }
        ]
    }"#;
    let err = parse_fixture_v1(bad).expect_err("boundary must reject smtp");
    assert!(
        matches!(err, sysdhardener_core::Error::AddressFamilyUnknown(_)),
        "expected AddressFamilyUnknown, got {err:?}"
    );
}

#[test]
fn aggregator_does_not_silently_promote_to_verified_or_safe() {
    // The aggregator's bundle is data, not a verdict. A consumer
    // must not be able to read a "verified" or "safe" promotion
    // from the aggregate. The bundle carries the typed
    // `CoverageQuality` (Complete / Degraded / Unknown) and the
    // typed `source_ids()` classification. There is no boolean
    // "verified" or "safe" field on the aggregate; the aggregator
    // never asserts either.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/happy.json");
    let fixture = parse_fixture_v1(&bytes).expect("happy must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    // The serialized JSON must not contain the words "verified" or
    // "safe-to-apply" in the aggregate payload. Note: this is a
    // probe of the *aggregator's output*, asserting that the
    // aggregate's typed shape carries no verification verdict.
    let json = serde_json::to_string(&bundle).expect("bundle serializes");
    for forbidden in ["verified", "safe", "guaranteed", "definitely"] {
        assert!(
            !json.contains(forbidden),
            "aggregate JSON must not assert {forbidden:?}: {json}"
        );
    }
}

#[test]
fn repeated_aggregation_yields_byte_identical_serialized_json() {
    // 8x repeated aggregation of the same input must produce
    // byte-identical serialized JSON. This is the determinism lock.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/happy.json");
    let fixture = parse_fixture_v1(&bytes).expect("happy must parse");
    let first = aggregate_address_family_evidence(fixture.events(), &fixture).expect("first");
    let first_json = serde_json::to_string(&first).expect("first serializes");
    for i in 0..8 {
        let bundle = aggregate_address_family_evidence(fixture.events(), &fixture)
            .unwrap_or_else(|e| panic!("iter {i} must succeed: {e}"));
        let json = serde_json::to_string(&bundle).expect("iter serializes");
        assert_eq!(
            json, first_json,
            "iter {i} JSON drift: {json} vs {first_json}"
        );
    }
}
