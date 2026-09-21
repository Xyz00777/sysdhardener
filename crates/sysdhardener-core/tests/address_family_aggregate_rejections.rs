//! Typed-discriminant rejection tests for the address-family
//! aggregator.
//!
//! The aggregator is **pure**: it accepts a typed `&[ObservedEvent]`
//! slice plus a typed `&Fixture` and returns either a typed bundle or
//! a typed `Error`. There are no string-keyed error paths and no
//! silently-coerced mismatches. Each rejection class produces a
//! distinct, machine-consumable discriminant so the recommendation
//! rule can branch on the failure mode without parsing
//! prose.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on rejection discriminants"
)]

use sysdhardener_core::{
    AddressFamily, Error, ObservedEvent, aggregate_address_family_evidence, parse_fixture_v1,
};

fn make_one_unix_fixture() -> Vec<u8> {
    br#"{
        "schema_version": 1,
        "fixture_id": "one-unix",
        "first_timestamp_unix_ms": 100,
        "last_timestamp_unix_ms": 100,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            { "source_id": "SRC-01", "event_id": "a1", "timestamp_unix_ms": 100, "address_family": "unix", "outcome": "success", "args": "a" }
        ]
    }"#
    .to_vec()
}

fn make_three_unix_fixture() -> Vec<u8> {
    br#"{
        "schema_version": 1,
        "fixture_id": "three-unix",
        "first_timestamp_unix_ms": 100,
        "last_timestamp_unix_ms": 300,
        "coverage": "complete",
        "seen_events": 3,
        "dropped_events": 0,
        "events": [
            { "source_id": "SRC-01", "event_id": "a1", "timestamp_unix_ms": 100, "address_family": "unix", "outcome": "success", "args": "a" },
            { "source_id": "SRC-01", "event_id": "a2", "timestamp_unix_ms": 200, "address_family": "unix", "outcome": "success", "args": "b" },
            { "source_id": "SRC-01", "event_id": "a3", "timestamp_unix_ms": 300, "address_family": "unix", "outcome": "success", "args": "c" }
        ]
    }"#
    .to_vec()
}

#[test]
fn empty_events_with_nonempty_fixture_declares_event_count_mismatch() {
    let bytes = make_three_unix_fixture();
    let fixture = parse_fixture_v1(&bytes).expect("three-unix must parse");
    let empty: Vec<ObservedEvent> = Vec::new();
    let err = aggregate_address_family_evidence(&empty, &fixture)
        .expect_err("empty events + nonempty declared count must reject");
    assert!(
        matches!(
            err,
            Error::EventCountMismatch {
                declared: 3,
                actual: 0
            }
        ),
        "expected EventCountMismatch{{declared:3, actual:0}}, got {err:?}"
    );
}

#[test]
fn too_many_events_relative_to_fixture_declares_event_count_mismatch() {
    let bytes = make_one_unix_fixture();
    let fixture = parse_fixture_v1(&bytes).expect("one-unix must parse");
    // Build a two-event list by parsing a sibling fixture and re-using
    // its events; this guarantees the events are typed.
    let other_bytes = make_three_unix_fixture();
    let other_fixture = parse_fixture_v1(&other_bytes).expect("three-unix must parse");
    let two_events: Vec<ObservedEvent> = other_fixture.events().iter().take(2).cloned().collect();
    assert_eq!(two_events.len(), 2);
    let err = aggregate_address_family_evidence(&two_events, &fixture)
        .expect_err("two events with declared=1 must reject");
    assert!(
        matches!(
            err,
            Error::EventCountMismatch {
                declared: 1,
                actual: 2
            }
        ),
        "expected EventCountMismatch{{declared:1, actual:2}}, got {err:?}"
    );
}

#[test]
fn dropped_events_greater_than_seen_is_a_boundary_failure_not_an_aggregator_failure() {
    // The boundary already rejects dropped > seen. Confirm the
    // boundary's typed discriminant is what the caller sees, and
    // that the aggregator is never reached with an inconsistent
    // fixture.
    let bytes = br#"{
        "schema_version": 1,
        "fixture_id": "inconsistent",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 5,
        "events": []
    }"#
    .to_vec();
    let err = parse_fixture_v1(&bytes).expect_err("boundary must reject dropped > seen");
    assert!(
        matches!(
            err,
            Error::EventLossInconsistent {
                seen: 1,
                dropped: 5
            }
        ),
        "expected EventLossInconsistent{{seen:1, dropped:5}}, got {err:?}"
    );
}

#[test]
fn timestamp_reversal_is_a_boundary_failure_not_an_aggregator_failure() {
    // first > last is rejected at the boundary; the aggregator never
    // sees a reversed window.
    let bytes = br#"{
        "schema_version": 1,
        "fixture_id": "reversed",
        "first_timestamp_unix_ms": 100,
        "last_timestamp_unix_ms": 50,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#
    .to_vec();
    let err = parse_fixture_v1(&bytes).expect_err("boundary must reject first > last");
    assert!(
        matches!(
            err,
            Error::TimestampReversed {
                first_unix_ms: 100,
                last_unix_ms: 50
            }
        ),
        "expected TimestampReversed{{first_unix_ms:100, last_unix_ms:50}}, got {err:?}"
    );
}

#[test]
fn aggregator_preserves_coverage_unknown_distinctly_from_degraded() {
    // Coverage: "unknown" is a distinct tag. The aggregator must
    // surface it through CoverageQuality::Unknown.
    let bytes = br#"{
        "schema_version": 1,
        "fixture_id": "unknown-cov",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0,
        "coverage": "unknown",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#
    .to_vec();
    let fixture = parse_fixture_v1(&bytes).expect("unknown-cov must parse");
    let events: Vec<ObservedEvent> = fixture.events().to_vec();
    let bundle = aggregate_address_family_evidence(&events, &fixture)
        .expect("unknown-coverage empty fixture must aggregate");
    assert_eq!(
        bundle.coverage(),
        sysdhardener_core::CoverageQuality::Unknown
    );
}

#[test]
fn aggregator_does_not_silently_emit_an_entry_for_a_family_not_in_input() {
    // After aggregating a unix-only fixture, get(AddressFamily::Inet)
    // must return None — the aggregator must not fabricate an entry
    // for an unobserved family just because a recommendation might
    // want one.
    let bytes = make_one_unix_fixture();
    let fixture = parse_fixture_v1(&bytes).expect("one-unix must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    assert!(bundle.get(AddressFamily::Unix).is_some());
    assert!(
        bundle.get(AddressFamily::Inet).is_none(),
        "absent family must not be fabricated"
    );
    assert!(
        bundle.get(AddressFamily::Inet6).is_none(),
        "absent family must not be fabricated"
    );
    assert!(
        bundle.get(AddressFamily::Netlink).is_none(),
        "absent family must not be fabricated"
    );
    assert!(
        bundle.get(AddressFamily::Packet).is_none(),
        "absent family must not be fabricated"
    );
}

#[test]
fn aggregator_repeated_calls_yield_identical_bundles_no_silent_drift() {
    // Run aggregation 16x on the same input. Every iteration must
    // produce the same key + count + first/last + representative +
    // coverage/loss. This is the determinism + no-shared-state lock.
    let bytes = make_three_unix_fixture();
    let fixture = parse_fixture_v1(&bytes).expect("three-unix must parse");
    let events: Vec<ObservedEvent> = fixture.events().to_vec();
    let first = aggregate_address_family_evidence(&events, &fixture).expect("first aggregation");
    let first_unix = first.get(AddressFamily::Unix).expect("unix in first");
    for i in 0..16 {
        let bundle = aggregate_address_family_evidence(&events, &fixture)
            .unwrap_or_else(|e| panic!("iteration {i} must succeed: {e}"));
        let unix = bundle.get(AddressFamily::Unix).expect("unix present");
        assert_eq!(unix.count(), first_unix.count(), "iter {i} count drift");
        assert_eq!(unix.key(), first_unix.key(), "iter {i} key drift");
        assert_eq!(
            unix.first_timestamp_unix_ms(),
            first_unix.first_timestamp_unix_ms(),
            "iter {i} first drift"
        );
        assert_eq!(
            unix.last_timestamp_unix_ms(),
            first_unix.last_timestamp_unix_ms(),
            "iter {i} last drift"
        );
        assert_eq!(
            unix.representative_args(),
            first_unix.representative_args(),
            "iter {i} representative_args drift"
        );
        assert_eq!(
            unix.representative_event_id(),
            first_unix.representative_event_id(),
            "iter {i} representative_event_id drift"
        );
        assert_eq!(
            bundle.coverage(),
            first.coverage(),
            "iter {i} coverage drift"
        );
    }
}
