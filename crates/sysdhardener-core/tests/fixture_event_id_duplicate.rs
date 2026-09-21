//! Duplicate-`event_id` rejection contract for the v1 fixture
//! boundary.
//!
//! Locked invariant: any duplicated `event_id` is rejected with
//! `Error::EventIdDuplicate`, carrying the first and second
//! occurrence indices. The reported pair is the one whose *first*
//! occurrence is earliest in wire order (the outer-loop scan
//! semantics), with its first later match as the second index.
//! The indices are part of the typed contract the uniqueness pass
//! must preserve.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the source contract"
)]

use sysdhardener_core::{Error, parse_fixture_v1};

#[test]
fn duplicate_event_id_is_rejected_with_typed_discriminant() {
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "duplicate-event-id",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 2,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-dup",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            },
            {
                "source_id": "SRC-01",
                "event_id": "evt-dup",
                "timestamp_unix_ms": 1,
                "address_family": "inet",
                "outcome": "success",
                "args": "y"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("duplicate event_id must be rejected at the boundary");
    match err {
        Error::EventIdDuplicate {
            event_id,
            first_index,
            second_index,
        } => {
            assert_eq!(event_id, "evt-dup");
            assert_eq!(first_index, 0, "first occurrence of the duplicated id");
            assert_eq!(second_index, 1, "second occurrence of the duplicated id");
        }
        other => panic!("expected Error::EventIdDuplicate, got {other:?}"),
    }
}

#[test]
fn duplicate_event_id_reports_earliest_duplicate_pair_with_exact_indices() {
    // Events: evt-a, evt-b, evt-b, evt-a. The nested-loop scan
    // reports the duplicate whose *first* index is smallest: the
    // outer loop reaches i=0 (evt-a) and finds its second
    // occurrence at j=3 before the evt-b pair (1,2) is scanned,
    // so the reported pair is (0, 3, evt-a). The indices are part
    // of the typed contract the O(n) replacement must preserve.
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "duplicate-pair-order",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 3,
        "coverage": "complete",
        "seen_events": 4,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-a",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            },
            {
                "source_id": "SRC-01",
                "event_id": "evt-b",
                "timestamp_unix_ms": 1,
                "address_family": "inet",
                "outcome": "success",
                "args": "y"
            },
            {
                "source_id": "SRC-01",
                "event_id": "evt-b",
                "timestamp_unix_ms": 2,
                "address_family": "inet6",
                "outcome": "success",
                "args": "z"
            },
            {
                "source_id": "SRC-01",
                "event_id": "evt-a",
                "timestamp_unix_ms": 3,
                "address_family": "netlink",
                "outcome": "success",
                "args": "w"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(bad.as_bytes())
        .expect_err("duplicate event_id must be rejected at the boundary");
    match err {
        Error::EventIdDuplicate {
            event_id,
            first_index,
            second_index,
        } => {
            assert_eq!(event_id, "evt-a");
            assert_eq!(first_index, 0);
            assert_eq!(second_index, 3);
        }
        other => panic!("expected Error::EventIdDuplicate, got {other:?}"),
    }
}
