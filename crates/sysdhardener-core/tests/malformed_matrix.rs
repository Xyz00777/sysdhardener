//! Malformed-fixture matrix: one test per rejected boundary class.
//!
//! Each test below drives a *different* boundary class through
//! [`parse_fixture_v1`] and asserts the *exact* typed error
//! discriminant; the happy path lives in `contract.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]
#![allow(
    non_snake_case,
    reason = "SRC-NN test names mirror the source-registry prefix under test"
)]

use sysdhardener_core::{Error, parse_fixture_v1};

#[test]
fn rejects_schema_999() {
    let bad = br#"{"schema_version": 999, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 0, "coverage": "complete", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    let err = parse_fixture_v1(bad).expect_err("schema 999 must be rejected");
    assert!(matches!(err, Error::SchemaUnknown { .. }));
}

#[test]
fn rejects_schema_0() {
    let bad = br#"{"schema_version": 0, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 0, "coverage": "complete", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    let err = parse_fixture_v1(bad).expect_err("schema 0 must be rejected");
    assert!(matches!(err, Error::SchemaUnknown { .. }));
}

#[test]
fn rejects_negative_schema() {
    let bad = br#"{"schema_version": -1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 0, "coverage": "complete", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    let err = parse_fixture_v1(bad).expect_err("negative schema must be rejected");
    assert!(
        matches!(err, Error::JsonShape(_) | Error::JsonSyntax { .. }),
        "negative schema must be rejected as a shape or syntax error, got {err:?}"
    );
}

#[test]
fn rejects_missing_schema_version() {
    let bad = br#"{"fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 0, "coverage": "complete", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    let err = parse_fixture_v1(bad).expect_err("missing schema_version must be rejected");
    assert!(matches!(err, Error::FixtureFieldMissing { .. }));
}

#[test]
fn rejects_SRC_lowercase_prefix() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "src-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "unix", "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("lowercase src- prefix must be rejected");
    assert!(matches!(err, Error::SourceIdMalformed(_)));
}

#[test]
fn rejects_SRC_with_leading_whitespace() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": " SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "unix", "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("whitespace-prefixed source_id must be rejected");
    assert!(matches!(err, Error::SourceIdMalformed(_)));
}

#[test]
fn rejects_SRC_just_prefix() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "unix", "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("SRC- without digits must be rejected");
    assert!(matches!(err, Error::SourceIdMalformed(_)));
}

#[test]
fn rejects_reversed_timestamps_with_event_inside_window() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 5000, "last_timestamp_unix_ms": 1000, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 2000, "address_family": "unix", "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("reversed window must be rejected");
    assert!(matches!(err, Error::TimestampReversed { .. }));
}

#[test]
fn rejects_unknown_address_family_capitalized() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "UNIX", "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("capitalized address_family must be rejected");
    assert!(matches!(err, Error::AddressFamilyUnknown(_)));
}

#[test]
fn rejects_unknown_outcome_typo() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "unix", "outcome": "sucess", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("typo'd outcome must be rejected");
    assert!(matches!(err, Error::EventOutcomeUnknown(_)));
}

#[test]
fn rejects_unknown_coverage_typo() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complet", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    let err = parse_fixture_v1(bad).expect_err("typo'd coverage must be rejected");
    assert!(matches!(err, Error::CoverageTagUnknown(_)));
}

#[test]
fn rejects_truncated_json() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x""#;
    let err = parse_fixture_v1(bad).expect_err("truncated JSON must be rejected");
    assert!(matches!(err, Error::JsonSyntax { .. }));
}

#[test]
fn rejects_garbage_bytes() {
    let bad = b"\xff\xfe\xfd not json at all";
    let err = parse_fixture_v1(bad).expect_err("garbage bytes must be rejected");
    assert!(matches!(err, Error::JsonSyntax { .. }));
}

#[test]
fn rejects_empty_input() {
    let bad: &[u8] = b"";
    let err = parse_fixture_v1(bad).expect_err("empty input must be rejected");
    assert!(matches!(err, Error::JsonSyntax { .. }));
}

#[test]
fn rejects_event_missing_address_family() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "outcome": "success", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("event missing address_family must be rejected");
    assert!(matches!(err, Error::FixtureFieldMissing { .. }));
}

#[test]
fn rejects_event_missing_outcome() {
    let bad = br#"{"schema_version": 1, "fixture_id": "x", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1, "dropped_events": 0, "events": [{"source_id": "SRC-01", "event_id": "evt-001", "timestamp_unix_ms": 0, "address_family": "unix", "args": "x"}]}"#;
    let err = parse_fixture_v1(bad).expect_err("event missing outcome must be rejected");
    assert!(matches!(err, Error::FixtureFieldMissing { .. }));
}

#[test]
fn accepts_valid_fixture_with_zero_events() {
    let ok = br#"{"schema_version": 1, "fixture_id": "empty", "first_timestamp_unix_ms": 0, "last_timestamp_unix_ms": 0, "coverage": "complete", "seen_events": 0, "dropped_events": 0, "events": []}"#;
    parse_fixture_v1(ok).expect("zero events with equal timestamps is valid");
}
