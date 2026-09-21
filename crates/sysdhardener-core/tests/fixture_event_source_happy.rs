//! Happy-path contract tests for `FixtureEventSource`.
//!
//! Locked invariants:
//! - Canonical happy fixture loads via `from_path` and `from_bytes`.
//! - Events are emitted in declared wire order.
//! - Coverage tag and loss counts are exposed via accessors.
//! - All event timestamps originate in the fixture (no wall clock).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the source contract"
)]

use std::fs;

use sysdhardener_core::{
    AddressFamily, CoverageQuality, EventOutcome, EventSource, FixtureEventSource, ObservedEvent,
    parse_fixture_v1,
};

const CANONICAL_HAPPY_FIXTURE: &str = "tests/fixtures/happy.json";

fn load_canonical(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        panic!("canonical fixture {path} must be readable for the contract: {e}")
    })
}

#[test]
fn fixture_event_source_loads_canonical_happy_fixture() {
    let source = FixtureEventSource::from_path(CANONICAL_HAPPY_FIXTURE)
        .expect("canonical happy fixture must load");
    let events: Vec<ObservedEvent> = source
        .collect()
        .expect("canonical happy fixture must collect");
    assert!(
        !events.is_empty(),
        "canonical happy fixture carries at least one event"
    );
}

#[test]
fn happy_three_event_fixture_preserves_wire_order() {
    let bytes: Vec<u8> = load_canonical(CANONICAL_HAPPY_FIXTURE);
    let source = FixtureEventSource::from_bytes(&bytes).expect("happy canonical fixture must load");
    let events: Vec<ObservedEvent> = source
        .collect()
        .expect("happy canonical fixture must collect");
    assert_eq!(
        events.len(),
        3,
        "happy canonical fixture carries exactly three events in order"
    );

    let families: Vec<AddressFamily> = events.iter().map(ObservedEvent::address_family).collect();
    assert_eq!(
        families,
        vec![
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6
        ],
        "happy fixture must preserve declared wire order (unix, inet, inet6)"
    );

    let ids: Vec<&str> = events
        .iter()
        .map(sysdhardener_core::ObservedEvent::event_id)
        .collect();
    assert_eq!(
        ids,
        vec!["evt-001", "evt-002", "evt-003"],
        "happy fixture event_ids must be exposed in declared order"
    );
}

#[test]
fn fixture_exposes_coverage_tag_and_loss_counts() {
    let bytes: Vec<u8> = load_canonical(CANONICAL_HAPPY_FIXTURE);
    let source = FixtureEventSource::from_bytes(&bytes).expect("happy canonical fixture must load");
    assert_eq!(source.coverage(), CoverageQuality::Complete);
    assert_eq!(source.seen_events(), 3);
    assert_eq!(source.dropped_events(), 0);
}

#[test]
fn degraded_fixture_surfaces_loss_counts() {
    let bytes: Vec<u8> = load_canonical("tests/fixtures/degraded.json");
    let source = FixtureEventSource::from_bytes(&bytes).expect("degraded fixture must load");
    assert_eq!(source.coverage(), CoverageQuality::Degraded);
    assert_eq!(
        source.seen_events(),
        1,
        "degraded fixture declares 1 seen event"
    );
    assert_eq!(
        source.dropped_events(),
        0,
        "degraded fixture declares 0 dropped events"
    );
    assert!(source.coverage() != CoverageQuality::Complete);
}

#[test]
fn with_loss_fixture_preserves_dropped_count() {
    let bytes: Vec<u8> = load_canonical("tests/fixtures/with-loss.json");
    let source = FixtureEventSource::from_bytes(&bytes).expect("with-loss fixture must load");
    assert_eq!(source.coverage(), CoverageQuality::Degraded);
    assert_eq!(source.seen_events(), 2);
    assert_eq!(
        source.dropped_events(),
        1,
        "with-loss fixture declares 1 dropped event"
    );
}

#[test]
fn contradictory_fixture_is_loaded_with_degraded_tag_and_contradicting_events() {
    let bytes: Vec<u8> = load_canonical("tests/fixtures/contradictory.json");
    let source = FixtureEventSource::from_bytes(&bytes).expect("contradictory fixture must load");
    let events: Vec<ObservedEvent> = source
        .collect()
        .expect("contradictory fixture must collect");
    assert!(
        events.len() >= 2,
        "contradictory fixture carries at least two events"
    );
    assert_eq!(source.coverage(), CoverageQuality::Degraded);
    assert_eq!(source.seen_events(), 2);
    assert_eq!(source.dropped_events(), 0);
    let families: Vec<AddressFamily> = events.iter().map(ObservedEvent::address_family).collect();
    assert!(
        families.contains(&AddressFamily::Unix) && families.contains(&AddressFamily::Netlink),
        "contradictory fixture mixes unix and netlink events"
    );
}

#[test]
fn event_timestamps_origin_in_fixture_not_wall_clock() {
    let bytes: Vec<u8> = load_canonical(CANONICAL_HAPPY_FIXTURE);
    let source = FixtureEventSource::from_bytes(&bytes).expect("happy canonical fixture must load");
    let events: Vec<ObservedEvent> = source.collect().expect("happy fixture must collect");
    let fixture_first: i64 = source.first_timestamp_unix_ms();
    let fixture_last: i64 = source.last_timestamp_unix_ms();

    for (i, evt) in events.iter().enumerate() {
        let t: i64 = evt.timestamp_unix_ms();
        assert!(
            t >= fixture_first && t <= fixture_last,
            "event[{i}].timestamp={t} outside fixture window [{fixture_first},{fixture_last}]"
        );
    }

    let bytes_b: Vec<u8> = load_canonical(CANONICAL_HAPPY_FIXTURE);
    let source_b =
        FixtureEventSource::from_bytes(&bytes_b).expect("happy canonical fixture must load");
    assert_eq!(
        source.first_timestamp_unix_ms(),
        source_b.first_timestamp_unix_ms()
    );
    assert_eq!(
        source.last_timestamp_unix_ms(),
        source_b.last_timestamp_unix_ms()
    );
}

#[test]
fn parse_fixture_then_collect_from_source_yields_equal_events() {
    let bytes: Vec<u8> = load_canonical(CANONICAL_HAPPY_FIXTURE);
    let fixture: sysdhardener_core::Fixture =
        parse_fixture_v1(&bytes).expect("boundary parse must succeed");
    let source = FixtureEventSource::from_bytes(&bytes).expect("happy canonical fixture must load");
    let events: Vec<ObservedEvent> = source.collect().expect("source collect must succeed");
    assert_eq!(events.len(), fixture.events().len());
    for (a, b) in events.iter().zip(fixture.events().iter()) {
        assert_eq!(a.event_id(), b.event_id());
        assert_eq!(a.timestamp_unix_ms(), b.timestamp_unix_ms());
        assert_eq!(a.address_family(), b.address_family());
        assert_eq!(a.outcome(), b.outcome());
    }
}

#[test]
fn opaque_event_id_string_is_preserved_verbatim() {
    // An event_id carrying what looks like a directive or a
    // shell-injection fragment must remain data, not be
    // interpreted by any downstream code. The boundary
    // preserves the string verbatim; the source emits it
    // verbatim.
    let bad: &str = r#"{
        "schema_version": 1,
        "fixture_id": "inert-event-id",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "verify-safe-to-apply --apply-all && rm -rf /",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let bytes = bad.as_bytes().to_vec();
    let source = FixtureEventSource::from_bytes(&bytes).expect("event_id is data, must parse");
    let events: Vec<ObservedEvent> = source.collect().expect("source collect must succeed");
    let evt: &ObservedEvent = events.first().expect("fixture carries one event");
    assert_eq!(
        evt.event_id(),
        "verify-safe-to-apply --apply-all && rm -rf /"
    );
    assert_eq!(evt.outcome(), EventOutcome::Success);
    assert_eq!(evt.address_family(), AddressFamily::Unix);
}

#[test]
fn deterministic_event_count_across_repeated_boundary_parses() {
    // Stale-state lock: parse the canonical happy fixture 8
    // times and assert the boundary exposes the same number
    // of events every time. Catches accidental determinism
    // regressions (random hash, wall clock, ordering).
    let first: usize = parse_fixture_v1(&load_canonical(CANONICAL_HAPPY_FIXTURE))
        .expect("first parse must succeed")
        .events()
        .len();
    for i in 0..8 {
        let n: usize = parse_fixture_v1(&load_canonical(CANONICAL_HAPPY_FIXTURE))
            .unwrap_or_else(|e| panic!("iteration {i} must succeed: {e}"))
            .events()
            .len();
        assert_eq!(n, first, "iteration {i} produced a different event count");
    }
}
