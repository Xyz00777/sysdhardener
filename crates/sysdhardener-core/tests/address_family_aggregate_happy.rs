//! Happy-path contract tests for the recommendation-local aggregate.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public aggregate contract"
)]

use std::fs;

use proptest::prelude::*;
use sysdhardener_core::{
    AddressFamily, AddressFamilyAggregate, CoverageQuality, EventOutcome, EventSource,
    FixtureEventSource, ObservedEvent, aggregate_address_family_evidence, parse_fixture_v1,
};

fn fixture(path: &str) -> sysdhardener_core::Fixture {
    let bytes = fs::read(path).expect("canonical fixture must be readable");
    parse_fixture_v1(&bytes).expect("canonical fixture must parse")
}

fn aggregate(path: &str) -> sysdhardener_core::AddressFamilyBundle {
    let parsed = fixture(path);
    aggregate_address_family_evidence(parsed.events(), &parsed).expect("fixture must aggregate")
}

#[test]
fn canonical_happy_fixture_loads_and_emits_stable_family_order() {
    let source = FixtureEventSource::from_path("tests/fixtures/happy.json")
        .expect("canonical happy fixture must load");
    let events: Vec<ObservedEvent> = source.collect().expect("source collect must succeed");
    let parsed =
        parse_fixture_v1(&fs::read("tests/fixtures/happy.json").expect("fixture must be readable"))
            .expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(&events, &parsed).expect("must aggregate");
    let families: Vec<AddressFamily> = bundle
        .entries()
        .map(AddressFamilyAggregate::family)
        .collect();
    assert_eq!(
        families,
        vec![
            AddressFamily::Unix,
            AddressFamily::Inet,
            AddressFamily::Inet6
        ]
    );
    assert_eq!(events.len(), 3);
}

#[test]
fn repeated_family_events_keep_count_and_extreme_timestamps() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "repeat", "first_timestamp_unix_ms": 5,
        "last_timestamp_unix_ms": 100, "coverage": "complete", "seen_events": 5,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"e1","timestamp_unix_ms":10,"address_family":"unix","outcome":"success","args":"a"},
          {"source_id":"SRC-01","event_id":"e2","timestamp_unix_ms":50,"address_family":"unix","outcome":"error","args":"b"},
          {"source_id":"SRC-01","event_id":"e3","timestamp_unix_ms":20,"address_family":"unix","outcome":"success","args":"c"},
          {"source_id":"SRC-01","event_id":"e4","timestamp_unix_ms":5,"address_family":"unix","outcome":"success","args":"d"},
          {"source_id":"SRC-01","event_id":"e5","timestamp_unix_ms":100,"address_family":"unix","outcome":"interrupted","args":"e"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("repeat fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let unix = bundle
        .get(AddressFamily::Unix)
        .expect("unix must be present");
    assert_eq!(unix.count(), 5);
    assert_eq!(unix.first_timestamp_unix_ms(), 5);
    assert_eq!(unix.last_timestamp_unix_ms(), 100);
}

#[test]
fn representative_is_first_event_and_sources_are_deduplicated_sorted() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "representative", "first_timestamp_unix_ms": 1,
        "last_timestamp_unix_ms": 3, "coverage": "complete", "seen_events": 3,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-02","event_id":"first","timestamp_unix_ms":2,"address_family":"unix","outcome":"success","args":"opaque"},
          {"source_id":"SRC-01","event_id":"second","timestamp_unix_ms":1,"address_family":"unix","outcome":"error","args":"other"},
          {"source_id":"SRC-02","event_id":"third","timestamp_unix_ms":3,"address_family":"unix","outcome":"interrupted","args":"third"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("representative fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let unix = bundle
        .get(AddressFamily::Unix)
        .expect("unix must be present");
    assert_eq!(unix.representative_event_id(), "first");
    assert_eq!(unix.representative_args(), "opaque");
    assert_eq!(unix.representative_outcome(), EventOutcome::Success);
    assert_eq!(unix.source_ids(), vec!["SRC-01", "SRC-02"]);
}

#[test]
fn coverage_and_loss_propagate_to_bundle_and_entries() {
    let parsed = fixture("tests/fixtures/with-loss.json");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    assert_eq!(bundle.coverage(), CoverageQuality::Degraded);
    assert_eq!(bundle.seen_events(), 2);
    assert_eq!(bundle.dropped_events(), 1);
    for entry in bundle.entries() {
        assert_eq!(entry.coverage(), CoverageQuality::Degraded);
        assert_eq!(entry.seen_events(), 2);
        assert_eq!(entry.dropped_events(), 1);
    }
}

#[test]
fn contradictory_fixture_keeps_independent_family_source_provenance() {
    let bundle = aggregate("tests/fixtures/contradictory.json");
    let unix = bundle
        .get(AddressFamily::Unix)
        .expect("unix must be present");
    let netlink = bundle
        .get(AddressFamily::Netlink)
        .expect("netlink must be present");
    assert_eq!(unix.source_ids(), vec!["SRC-01"]);
    assert_eq!(netlink.source_ids(), vec!["SRC-02"]);
    assert_ne!(unix.key(), netlink.key());
}

#[test]
fn empty_fixture_produces_empty_local_bundle_with_metadata() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "empty", "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 0, "coverage": "unknown", "seen_events": 0,
        "dropped_events": 0, "events": []
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("empty fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    assert_eq!(bundle.entries().count(), 0);
    assert_eq!(bundle.coverage(), CoverageQuality::Unknown);
    assert_eq!(bundle.seen_events(), 0);
    assert_eq!(bundle.dropped_events(), 0);
    let json = serde_json::to_string(&bundle).expect("bundle serializes");
    assert!(json.contains("\"seen_events\":0"));
}

#[test]
fn explicit_key_is_stable_and_human_readable() {
    let first = aggregate("tests/fixtures/happy.json");
    let second = aggregate("tests/fixtures/happy.json");
    let a = first
        .get(AddressFamily::Unix)
        .expect("unix must be present");
    let b = second
        .get(AddressFamily::Unix)
        .expect("unix must be present");
    assert!(a.key().starts_with("af=unix|src=SRC-01"));
    assert_eq!(a.key(), b.key());
    assert!(!a.key().chars().all(|c| c.is_ascii_digit() || c == '-'));
}

#[test]
fn separate_aggregations_do_not_share_local_state() {
    let a = br#"{"schema_version":1,"fixture_id":"a","first_timestamp_unix_ms":0,"last_timestamp_unix_ms":0,"coverage":"complete","seen_events":1,"dropped_events":0,"events":[{"source_id":"SRC-01","event_id":"a","timestamp_unix_ms":0,"address_family":"unix","outcome":"success","args":"a"}]}"#;
    let b = br#"{"schema_version":1,"fixture_id":"b","first_timestamp_unix_ms":0,"last_timestamp_unix_ms":0,"coverage":"complete","seen_events":1,"dropped_events":0,"events":[{"source_id":"SRC-01","event_id":"b","timestamp_unix_ms":0,"address_family":"inet","outcome":"success","args":"b"}]}"#;
    let fa = parse_fixture_v1(a).expect("a must parse");
    let fb = parse_fixture_v1(b).expect("b must parse");
    let ba = aggregate_address_family_evidence(fa.events(), &fa).expect("a aggregate");
    let bb = aggregate_address_family_evidence(fb.events(), &fb).expect("b aggregate");
    assert!(ba.get(AddressFamily::Unix).is_some());
    assert!(ba.get(AddressFamily::Inet).is_none());
    assert!(bb.get(AddressFamily::Inet).is_some());
    assert!(bb.get(AddressFamily::Unix).is_none());
}

#[test]
fn other_families_sorted_deterministically() {
    let e1 = ObservedEvent::new(
        sysdhardener_core::SourceId::from_static("SRC-01"),
        "e1".to_string(),
        sysdhardener_core::FixtureTimestamp::from_raw_checked(0),
        AddressFamily::Other("zebra"),
        EventOutcome::Success,
        "z".to_string(),
    );
    let e2 = ObservedEvent::new(
        sysdhardener_core::SourceId::from_static("SRC-01"),
        "e2".to_string(),
        sysdhardener_core::FixtureTimestamp::from_raw_checked(0),
        AddressFamily::Other("alpha"),
        EventOutcome::Success,
        "a".to_string(),
    );
    let fixture = sysdhardener_core::Fixture::from_events(vec![e1, e2]);
    let bundle = aggregate_address_family_evidence(fixture.events(), &fixture).expect("bundle");
    let families: Vec<AddressFamily> = bundle
        .entries()
        .map(AddressFamilyAggregate::family)
        .collect();
    assert_eq!(
        families,
        vec![AddressFamily::Other("alpha"), AddressFamily::Other("zebra")]
    );
}

proptest! {
    #[test]
    fn property_all_three_event_permutations_preserve_family_summary(
        order in prop::sample::select(vec![
            [0usize, 1, 2], [0, 2, 1], [1, 0, 2],
            [1, 2, 0], [2, 0, 1], [2, 1, 0],
        ])
    ) {
        let parsed = fixture("tests/fixtures/happy.json");
        let baseline = aggregate_address_family_evidence(parsed.events(), &parsed)
            .expect("canonical fixture must aggregate");
        let events: Vec<ObservedEvent> = order
            .iter()
            .map(|index| parsed.events().get(*index).expect("fixed index").clone())
            .collect();
        let shuffled = aggregate_address_family_evidence(&events, &parsed)
            .expect("permuted fixture must aggregate");
        for family in [AddressFamily::Unix, AddressFamily::Inet, AddressFamily::Inet6] {
            let expected = baseline.get(family).expect("baseline family");
            let actual = shuffled.get(family).expect("shuffled family");
            prop_assert_eq!(actual.key(), expected.key());
            prop_assert_eq!(actual.count(), expected.count());
            prop_assert_eq!(actual.first_timestamp_unix_ms(), expected.first_timestamp_unix_ms());
            prop_assert_eq!(actual.last_timestamp_unix_ms(), expected.last_timestamp_unix_ms());
        }
    }
}
