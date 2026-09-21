//! Outcome-semantics contract tests:
//! the `RestrictAddressFamilies=` candidate's handling of
//! `EventOutcome::Unknown` (outcome-less eBPF evidence).
//!
//! For this directive the **attempt is the evidence**: a family the
//! service tries to use (bind/connect/sendmsg/recvmsg) is a family it
//! needs, even when the specific call's outcome is unverified (the
//! cgroup sockaddr hook fires before the operation completes).
//! Denying an attempted family would break the service with
//! EAFNOSUPPORT. Therefore:
//! - an `unknown`-outcome family IS recommended (like `Success`);
//! - an `unknown`-outcome family is NOT a failure contradiction
//!   (`ObservedWithoutSuccessfulUse` remains reserved for a
//!   representative `Error` outcome);
//! - the `Error` path still surfaces a failure contradiction.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public recommendation contract"
)]

use sysdhardener_core::{
    AddressFamily, Capability, ContradictionCondition, RestrictAddressFamilies,
    aggregate_address_family_evidence, parse_fixture_v1, recommend_restrict_address_families,
};

#[test]
fn unknown_outcome_family_is_recommended_not_contradicted() {
    // An `unknown`-outcome family (the eBPF observer
    // cannot see syscall returns) was attempted, therefore it is
    // needed: it must enter the allow-list and must NOT be a failure
    // contradiction.
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "unknown-outcome", "first_timestamp_unix_ms": 1,
        "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-14","event_id":"e1","timestamp_unix_ms":1,"address_family":"inet","outcome":"unknown","args":"ebpf op=connect"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("unknown-outcome fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must always surface");

    assert!(
        finding
            .recommended_families()
            .contains(&AddressFamily::Inet),
        "attempted family must be recommended even with unknown outcome"
    );
    assert!(
        !finding.contradiction_conditions().iter().any(|c| matches!(
            c,
            ContradictionCondition::ObservedWithoutSuccessfulUse {
                family: AddressFamily::Inet,
                ..
            }
        )),
        "unknown-outcome family must not be a failure contradiction"
    );
}

#[test]
fn error_outcome_still_surfaces_as_failure_contradiction() {
    // Only a representative `Error` outcome is a failure
    // contradiction; the allow-list must exclude it.
    let bytes = br#"{
        "schema_version": 1, "fixture_id": "error-outcome", "first_timestamp_unix_ms": 1,
        "last_timestamp_unix_ms": 1, "coverage": "complete", "seen_events": 1,
        "dropped_events": 0, "events": [
          {"source_id":"SRC-01","event_id":"e1","timestamp_unix_ms":1,"address_family":"netlink","outcome":"error","args":"socket"}
        ]
    }"#;
    let parsed = parse_fixture_v1(bytes).expect("error-outcome fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must always surface");

    assert!(
        finding.contradiction_conditions().iter().any(|c| matches!(
            c,
            ContradictionCondition::ObservedWithoutSuccessfulUse {
                family: AddressFamily::Netlink,
                ..
            }
        )),
        "error-outcome family must surface as a failure contradiction"
    );
    assert!(
        !finding
            .recommended_families()
            .contains(&AddressFamily::Netlink),
        "error-outcome family must not be recommended"
    );
}
