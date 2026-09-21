//! Public-API consumer test: compile against the public re-exports only.
//!
//! This test file is the consumer-side lock verifying that a consumer
//! can compile using only the declared public API. It deliberately uses only what is exported from the crate
//! root (`sysdhardener_core::*`), not any private module path. If the
//! public re-exports are removed, this test fails to compile.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    AddressFamily, CoverageQuality, EventOutcome, Fixture, Report, SchemaVersion, parse_fixture_v1,
    serialize_report_v1,
};

const SAMPLE: &str = r#"{
    "schema_version": 1,
    "fixture_id": "consumer-sample",
    "first_timestamp_unix_ms": 1700000000000,
    "last_timestamp_unix_ms": 1700000002000,
    "coverage": "complete",
    "seen_events": 3,
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
            "address_family": "inet6",
            "outcome": "error",
            "args": "connect"
        },
        {
            "source_id": "SRC-02",
            "event_id": "evt-003",
            "timestamp_unix_ms": 1700000002000,
            "address_family": "netlink",
            "outcome": "interrupted",
            "args": "bind"
        }
    ]
}"#;

#[test]
fn public_api_consumer_round_trip() {
    let fixture: Fixture = parse_fixture_v1(SAMPLE.as_bytes()).expect("public API parse");
    let version: SchemaVersion = fixture.schema_version();
    assert_eq!(version.get(), 1);

    let coverage: CoverageQuality = fixture.coverage();
    assert_eq!(coverage, CoverageQuality::Complete);

    assert_eq!(fixture.events().len(), 3);
    let families: Vec<AddressFamily> = fixture
        .events()
        .iter()
        .map(sysdhardener_core::ObservedEvent::address_family)
        .collect();
    assert_eq!(
        families,
        vec![
            AddressFamily::Unix,
            AddressFamily::Inet6,
            AddressFamily::Netlink,
        ]
    );
    let outcomes: Vec<EventOutcome> = fixture
        .events()
        .iter()
        .map(sysdhardener_core::ObservedEvent::outcome)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            EventOutcome::Success,
            EventOutcome::Error,
            EventOutcome::Interrupted,
        ]
    );

    // Empty report round-trips byte-stable.
    let report: Report<'_> = Report::empty_v1();
    let bytes: Vec<u8> = serialize_report_v1(&report).expect("public API serialize");
    let text = std::str::from_utf8(&bytes).expect("utf-8");
    assert!(text.contains("schema_version"));
    assert!(text.contains("findings"));
}

#[test]
fn public_api_source_id_accessor() {
    let fixture: Fixture = parse_fixture_v1(SAMPLE.as_bytes()).expect("parse");
    let events: &[sysdhardener_core::ObservedEvent] = fixture.events();
    let first = events.first().expect("SAMPLE has 3 events");
    let third = events.get(2).expect("SAMPLE has 3 events");
    assert_eq!(first.source_id().as_str(), "SRC-01");
    assert_eq!(third.source_id().as_str(), "SRC-02");
}

#[test]
fn public_api_timestamp_accessor() {
    let fixture: Fixture = parse_fixture_v1(SAMPLE.as_bytes()).expect("parse");
    let events: &[sysdhardener_core::ObservedEvent] = fixture.events();
    assert_eq!(
        events
            .first()
            .expect("SAMPLE has 3 events")
            .timestamp_unix_ms(),
        1_700_000_000_000
    );
    assert_eq!(
        events
            .get(1)
            .expect("SAMPLE has 3 events")
            .timestamp_unix_ms(),
        1_700_000_001_000
    );
    assert_eq!(
        events
            .get(2)
            .expect("SAMPLE has 3 events")
            .timestamp_unix_ms(),
        1_700_000_002_000
    );
}

#[test]
fn public_api_args_accessor_preserves_arbitrary_string() {
    let fixture: Fixture = parse_fixture_v1(SAMPLE.as_bytes()).expect("parse");
    let events: &[sysdhardener_core::ObservedEvent] = fixture.events();
    assert_eq!(
        events.first().expect("SAMPLE has 3 events").args(),
        "connect"
    );
    assert_eq!(
        events.get(1).expect("SAMPLE has 3 events").args(),
        "connect"
    );
    assert_eq!(events.get(2).expect("SAMPLE has 3 events").args(), "bind");
}
