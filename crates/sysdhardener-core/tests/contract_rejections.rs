//! Rejection contract tests: every typed error discriminant the
//! boundary emits is asserted explicitly here, in addition to the
//! positive-path coverage in `contract.rs` and the broader matrix in
//! `malformed_matrix.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{Error, parse_fixture_v1};

#[test]
fn schema_version_999_returns_typed_schema_unknown_error() {
    let bad: &str = r#"{
        "schema_version": 999,
        "fixture_id": "future",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;

    let err: Error =
        parse_fixture_v1(bad.as_bytes()).expect_err("schema 999 must be rejected at the boundary");
    match &err {
        Error::SchemaUnknown { found, supported } => {
            assert_eq!(
                *found, 999,
                "Error::SchemaUnknown must carry the actual found value"
            );
            assert!(
                supported.contains(&1u32),
                "supported list must include 1, got {supported:?}"
            );
        }
        other => panic!("expected Error::SchemaUnknown, got {other:?}"),
    }
}

#[test]
fn malformed_source_id_returns_typed_source_id_malformed() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "bad-src",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-xx",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;

    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("malformed SRC-xx must be rejected at the boundary");
    assert!(
        matches!(err, Error::SourceIdMalformed(_)),
        "expected Error::SourceIdMalformed, got {err:?}"
    );
}

#[test]
fn reversed_timestamps_return_typed_timestamp_reversed_error() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "reversed",
        "first_timestamp_unix_ms": 2000,
        "last_timestamp_unix_ms": 1000,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;

    let err: Error =
        parse_fixture_v1(bad.as_bytes()).expect_err("first>last must be rejected at the boundary");
    match &err {
        Error::TimestampReversed {
            first_unix_ms,
            last_unix_ms,
        } => {
            assert_eq!(*first_unix_ms, 2000);
            assert_eq!(*last_unix_ms, 1000);
        }
        other => panic!("expected Error::TimestampReversed, got {other:?}"),
    }
}

#[test]
fn unknown_address_family_tag_returns_typed_error() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "bad-family",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "garbage",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;

    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("unknown address_family tag must be rejected at the boundary");
    assert!(
        matches!(err, Error::AddressFamilyUnknown(_)),
        "expected Error::AddressFamilyUnknown, got {err:?}"
    );
}

#[test]
fn unknown_outcome_tag_returns_typed_error() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "bad-outcome",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "sideways",
                "args": "x"
            }
        ]
    }"#;

    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("unknown outcome tag must be rejected at the boundary");
    assert!(
        matches!(err, Error::EventOutcomeUnknown(_)),
        "expected Error::EventOutcomeUnknown, got {err:?}"
    );
}

#[test]
fn unknown_coverage_tag_returns_typed_error() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "bad-cov",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "sideways",
        "seen_events": 0,
        "dropped_events": 0,
        "events": []
    }"#;

    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("unknown coverage tag must be rejected at the boundary");
    assert!(
        matches!(err, Error::CoverageTagUnknown(_)),
        "expected Error::CoverageTagUnknown, got {err:?}"
    );
}

#[test]
fn malformed_json_syntax_returns_typed_error() {
    let bad: &str = r#"{ "schema_version": 1, "events": "#;
    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("truncated JSON must be rejected at the boundary");
    assert!(
        matches!(err, Error::JsonSyntax { .. }),
        "expected Error::JsonSyntax, got {err:?}"
    );
}

#[test]
fn missing_required_field_returns_typed_error() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "missing-events",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 0,
        "dropped_events": 0
    }"#;

    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("missing required field must be rejected at the boundary");
    match &err {
        Error::FixtureFieldMissing { field } => {
            assert_eq!(*field, "events");
        }
        other => panic!("expected Error::FixtureFieldMissing, got {other:?}"),
    }
}

#[test]
fn source_id_with_non_numeric_suffix_is_rejected() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "bad-src-suffix",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-1a",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(bad.as_bytes()).expect_err("SRC-1a must be rejected");
    assert!(
        matches!(err, Error::SourceIdMalformed(_)),
        "expected Error::SourceIdMalformed, got {err:?}"
    );
}

#[test]
fn empty_source_id_is_rejected() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "empty-src",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error =
        parse_fixture_v1(bad.as_bytes()).expect_err("empty source_id must be rejected");
    assert!(
        matches!(err, Error::SourceIdMalformed(_)),
        "expected Error::SourceIdMalformed, got {err:?}"
    );
}
