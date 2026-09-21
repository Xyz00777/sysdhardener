//! Tests for representative outcome resolution in address-family aggregation.
//!
//! Locked invariant:
//! If a service experiences an initial error for an address family
//! (e.g. non-blocking connect retry) but later has a successful
//! operation for that same family, the aggregate representative outcome
//! must reflect the successful use so that the family is recommended
//! rather than falsely excluded as `ObservedWithoutSuccessfulUse`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the aggregate and recommendation contract"
)]

use sysdhardener_core::{
    AddressFamily, Capability, EventOutcome, RestrictAddressFamilies,
    aggregate_address_family_evidence, parse_fixture_v1, recommend_restrict_address_families,
};

#[test]
fn initial_error_followed_by_success_upgrades_representative_outcome_to_success() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "error-then-success", "first_timestamp_unix_ms": 10,
        "last_timestamp_unix_ms": 20, "coverage": "complete", "seen_events": 2,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"fail1","timestamp_unix_ms":10,"address_family":"inet","outcome":"error","args":"connect fail"},
          {"source_id":"SRC-01","event_id":"succ2","timestamp_unix_ms":20,"address_family":"inet","outcome":"success","args":"connect ok"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed)
        .expect("aggregate must succeed");
    let inet = bundle
        .get(AddressFamily::Inet)
        .expect("inet must be present");
    assert_eq!(
        inet.representative_outcome(),
        EventOutcome::Success,
        "representative outcome must be upgraded to Success"
    );
    assert_eq!(
        inet.representative_event_id(),
        "succ2",
        "representative event id should point to the successful event"
    );

    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("recommendation must succeed");

    assert!(
        finding
            .recommended_families()
            .contains(&AddressFamily::Inet),
        "inet must be in recommended_families because successful use occurred"
    );
    assert!(
        !finding
            .contradiction_conditions()
            .iter()
            .any(|c| format!("{c:?}").contains("ObservedWithoutSuccessfulUse")),
        "must not record ObservedWithoutSuccessfulUse when successful use occurred"
    );
}

#[test]
fn all_errors_remain_error_and_excluded_from_recommendation() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "all-errors", "first_timestamp_unix_ms": 10,
        "last_timestamp_unix_ms": 20, "coverage": "complete", "seen_events": 2,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"fail1","timestamp_unix_ms":10,"address_family":"inet","outcome":"error","args":"connect fail"},
          {"source_id":"SRC-01","event_id":"fail2","timestamp_unix_ms":20,"address_family":"inet","outcome":"error","args":"connect fail2"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed)
        .expect("aggregate must succeed");
    let inet = bundle
        .get(AddressFamily::Inet)
        .expect("inet must be present");
    assert_eq!(
        inet.representative_outcome(),
        EventOutcome::Error,
        "representative outcome must remain Error"
    );

    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("recommendation must succeed");

    assert!(
        !finding
            .recommended_families()
            .contains(&AddressFamily::Inet),
        "inet must NOT be in recommended_families when all attempts failed"
    );
}

#[test]
fn interrupted_followed_by_success_upgrades_representative_outcome_to_success() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "interrupted-then-success", "first_timestamp_unix_ms": 10,
        "last_timestamp_unix_ms": 20, "coverage": "complete", "seen_events": 2,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"int1","timestamp_unix_ms":10,"address_family":"inet","outcome":"interrupted","args":"connect interrupted"},
          {"source_id":"SRC-01","event_id":"succ2","timestamp_unix_ms":20,"address_family":"inet","outcome":"success","args":"connect ok"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed)
        .expect("aggregate must succeed");
    let inet = bundle
        .get(AddressFamily::Inet)
        .expect("inet must be present");
    assert_eq!(
        inet.representative_outcome(),
        EventOutcome::Success,
        "representative outcome must be upgraded from Interrupted to Success"
    );
    assert_eq!(inet.representative_event_id(), "succ2");
}

#[test]
fn error_followed_by_interrupted_upgrades_representative_outcome_to_interrupted() {
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "error-then-interrupted", "first_timestamp_unix_ms": 10,
        "last_timestamp_unix_ms": 20, "coverage": "complete", "seen_events": 2,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"fail1","timestamp_unix_ms":10,"address_family":"inet","outcome":"error","args":"connect fail"},
          {"source_id":"SRC-01","event_id":"int2","timestamp_unix_ms":20,"address_family":"inet","outcome":"interrupted","args":"connect interrupted"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed)
        .expect("aggregate must succeed");
    let inet = bundle
        .get(AddressFamily::Inet)
        .expect("inet must be present");
    assert_eq!(
        inet.representative_outcome(),
        EventOutcome::Interrupted,
        "representative outcome must be upgraded from Error to Interrupted"
    );
    assert_eq!(inet.representative_event_id(), "int2");
}
