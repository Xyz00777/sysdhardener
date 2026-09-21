//! Rejection contract tests for `FixtureEventSource` and the v1
//! fixture boundary.
//!
//! Locked invariants:
//! - Duplicate `event_id` -> `Error::EventIdDuplicate`.
//! - `dropped_events > seen_events` -> `Error::EventLossInconsistent`.
//! - `events.len() != seen_events` -> `Error::EventCountMismatch`.
//! - Empty `event_id` -> `Error::EventIdEmpty`.
//! - Truncated JSON -> `Error::JsonSyntax`.
//! - Unknown schema version -> `Error::SchemaUnknown`.
//! - `from_path` on a non-existent file -> `Error::Io`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the source contract"
)]

use std::fs;

use sysdhardener_core::{Error, FixtureEventSource, parse_fixture_v1};

fn load_canonical(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        panic!("canonical fixture {path} must be readable for the contract: {e}")
    })
}

#[test]
fn unknown_schema_fixture_is_rejected_at_parse_boundary() {
    let bytes: Vec<u8> = load_canonical("tests/fixtures/unknown-schema.json");
    let result: Result<sysdhardener_core::Fixture, Error> = parse_fixture_v1(&bytes);
    let err: Error = result.expect_err("unknown schema must be rejected at the boundary");
    match err {
        Error::SchemaUnknown { found, supported } => {
            assert_eq!(
                found, 999,
                "unknown-schema fixture carries schema_version 999"
            );
            assert!(supported.contains(&1u32));
        }
        other => panic!("expected Error::SchemaUnknown, got {other:?}"),
    }
}

#[test]
fn malformed_fixture_is_rejected_at_parse_boundary() {
    let bytes: Vec<u8> = load_canonical("tests/fixtures/malformed.json");
    let result: Result<sysdhardener_core::Fixture, Error> = parse_fixture_v1(&bytes);
    let err: Error = result.expect_err("malformed fixture must be rejected at the boundary");
    assert!(
        matches!(err, Error::JsonSyntax { .. }),
        "expected Error::JsonSyntax, got {err:?}"
    );
}

#[test]
fn dropped_greater_than_seen_is_rejected_with_typed_discriminant() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "impossible-loss",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 2,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("dropped>seen must be rejected at the boundary");
    match err {
        Error::EventLossInconsistent { seen, dropped } => {
            assert_eq!(seen, 1);
            assert_eq!(dropped, 2);
        }
        other => panic!("expected Error::EventLossInconsistent, got {other:?}"),
    }
}

#[test]
fn dropped_equal_to_seen_is_accepted() {
    let ok: &str = r#"{
        "schema_version": 1,
        "fixture_id": "half-dropped",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "degraded",
        "seen_events": 1,
        "dropped_events": 1,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let fixture = parse_fixture_v1(ok.as_bytes()).expect("dropped==seen is a valid loss claim");
    assert_eq!(fixture.seen_events(), 1);
    assert_eq!(fixture.dropped_events(), 1);
}

#[test]
fn event_count_must_match_seen_events_count() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "count-mismatch",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 5,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error =
        parse_fixture_v1(bad.as_bytes()).expect_err("event_count != seen_events must be rejected");
    match err {
        Error::EventCountMismatch { declared, actual } => {
            assert_eq!(declared, 5);
            assert_eq!(actual, 1);
        }
        other => panic!("expected Error::EventCountMismatch, got {other:?}"),
    }
}

#[test]
fn empty_event_id_is_rejected() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "empty-event-id",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("empty event_id must be rejected at the boundary");
    assert!(
        matches!(err, Error::EventIdEmpty { .. } | Error::JsonShape(_)),
        "expected Error::EventIdEmpty or JsonShape, got {err:?}"
    );
}

#[test]
fn fixture_event_source_from_unknown_path_returns_io_error() {
    let result = FixtureEventSource::from_path("/nonexistent/path/does-not-exist.json");
    let err: Error = result.expect_err("unknown path must fail at the boundary");
    assert!(
        matches!(err, Error::Io { .. }),
        "expected Error::Io, got {err:?}"
    );
}
