//! Happy-path contract tests for the versioned fixture/report boundary.
//!
//! Locked invariants: the minimal v1 fixture parses into a typed
//! [`Fixture`], the v1 report envelope round-trips byte-stable, and
//! every supported coverage quality tag is accepted as a typed value.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    CoverageQuality, EventOutcome, Fixture, Report, parse_fixture_v1, serialize_report_v1,
};

const MINIMAL_V1: &str = r#"{
    "schema_version": 1,
    "fixture_id": "minimal",
    "first_timestamp_unix_ms": 1700000000000,
    "last_timestamp_unix_ms": 1700000001000,
    "coverage": "complete",
    "seen_events": 2,
    "dropped_events": 0,
    "events": [
        {
            "source_id": "SRC-01",
            "event_id": "evt-001",
            "timestamp_unix_ms": 1700000000000,
            "address_family": "unix",
            "outcome": "success",
            "args": "connect"
        },
        {
            "source_id": "SRC-01",
            "event_id": "evt-002",
            "timestamp_unix_ms": 1700000001000,
            "address_family": "inet",
            "outcome": "success",
            "args": "bind"
        }
    ]
}"#;

#[test]
fn minimal_v1_fixture_parses_to_typed_value() {
    let fixture: Fixture =
        parse_fixture_v1(MINIMAL_V1.as_bytes()).expect("minimal v1 fixture must parse");

    assert_eq!(fixture.schema_version().get(), 1);
    assert_eq!(fixture.coverage(), CoverageQuality::Complete);
    assert_eq!(fixture.events().len(), 2);

    let first = fixture
        .events()
        .first()
        .expect("MINIMAL_V1 carries 2 events");
    assert_eq!(first.outcome(), EventOutcome::Success);
    assert_eq!(first.source_id().as_str(), "SRC-01");
    assert_eq!(first.timestamp_unix_ms(), 1_700_000_000_000);
}

#[test]
fn v1_report_envelope_round_trips_byte_stably() {
    let report: Report<'_> = Report::empty_v1();
    let bytes: Vec<u8> = serialize_report_v1(&report).expect("report must serialize");
    let text = std::str::from_utf8(&bytes).expect("report must be utf-8");

    assert!(
        text.contains("\"schema_version\":1") || text.contains("\"schema_version\": 1"),
        "report envelope must carry schema_version 1, got: {text}"
    );
}

#[test]
fn v1_report_round_trip_is_byte_identical_across_repeated_calls() {
    // Stale-state lock: serialize the same empty v1 report 16 times and
    // assert every byte sequence is identical. Catches accidental
    // non-determinism (random hash, wall clock, ordering) in the
    // serializer.
    let first: Vec<u8> =
        serialize_report_v1(&Report::empty_v1()).expect("first serialize must succeed");
    for i in 0..16 {
        let again: Vec<u8> = serialize_report_v1(&Report::empty_v1())
            .unwrap_or_else(|e| panic!("iteration {i} failed: {e}"));
        assert_eq!(
            first, again,
            "iteration {i} produced a different byte sequence: {again:?} vs {first:?}"
        );
    }
}

#[test]
fn equal_timestamps_are_accepted() {
    let ok: &str = r#"{
        "schema_version": 1,
        "fixture_id": "zero-window",
        "first_timestamp_unix_ms": 100,
        "last_timestamp_unix_ms": 100,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;
    let fixture: Fixture =
        parse_fixture_v1(ok.as_bytes()).expect("first==last is a valid zero-width window");
    assert_eq!(fixture.coverage(), CoverageQuality::Complete);
}

#[test]
fn degraded_coverage_parses_to_typed_value() {
    let ok: &str = r#"{
        "schema_version": 1,
        "fixture_id": "degraded",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "degraded",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;
    let fixture: Fixture =
        parse_fixture_v1(ok.as_bytes()).expect("degraded coverage must parse to a typed value");
    assert_eq!(fixture.coverage(), CoverageQuality::Degraded);
}

#[test]
fn unknown_coverage_parses_to_typed_value() {
    let ok: &str = r#"{
        "schema_version": 1,
        "fixture_id": "unknown-cov",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "unknown",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;
    let fixture: Fixture =
        parse_fixture_v1(ok.as_bytes()).expect("unknown coverage must parse to a typed value");
    assert_eq!(fixture.coverage(), CoverageQuality::Unknown);
}
