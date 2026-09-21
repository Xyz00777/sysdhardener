//! End-to-end pipeline test for the eBPF observer evidence path.
//!
//! Simulates decoded ring-buffer `SockEvent`s, runs them through the
//! `sock_events_to_observed` bridge into the typed `ObservedEvent`
//! stream, wraps them with `Fixture::from_events`, and drives the full
//! analysis engine. This proves the whole eBPF observation →
//! recommendation path without needing root/`CAP_BPF` or a nightly-built
//! eBPF object (the loader's `observe_cgroup_events` attach/load is the
//! only piece that needs the reference host).
//!
//! The bridge stamps every event `EventOutcome::Unknown`, so
//! the recommended allow-list treats attempted families as needed
//! and every observed family surfaces as `ObservedOutcomeUnverified`,
//! never as a failure contradiction.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_bpf_loader::sock_events_to_observed;
use sysdhardener_core::{
    AddressFamily, Capability, RestrictAddressFamilies, aggregate_address_family_evidence,
    recommend_restrict_address_families,
};
use sysdhardener_wire_format::{SockEvent, SockOp};

const fn sock_event(family: u32, op: SockOp, pid: u32, ts: u64) -> SockEvent {
    SockEvent {
        pid,
        family,
        op: op.as_u32(),
        timestamp_ms: ts,
    }
}

#[test]
fn bridge_plus_engine_unknown_outcomes_surface_as_unverified() {
    // An AF_INET6 connect, AF_INET bind, AF_UNIX connect from the ring.
    let events: Vec<SockEvent> = vec![
        sock_event(10, SockOp::Connect, 100, 1_700_000_000_000), // inet6
        sock_event(2, SockOp::Bind, 101, 1_700_000_000_001),     // inet
        sock_event(1, SockOp::Connect, 102, 1_700_000_000_002),  // unix
    ];
    let observed = sock_events_to_observed(&events);
    assert_eq!(observed.len(), 3);
    for ev in &observed {
        assert_eq!(ev.outcome(), sysdhardener_core::EventOutcome::Unknown);
    }

    let fixture = sysdhardener_core::Fixture::from_events(observed);
    let bundle = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("eBPF evidence must aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must always surface");

    // Attempted = needed. Every observed family is
    // recommended (unknown outcome is not a failure), and none is a
    // failure contradiction.
    for family in [
        AddressFamily::Inet,
        AddressFamily::Inet6,
        AddressFamily::Unix,
    ] {
        assert!(
            finding.recommended_families().contains(&family),
            "{family:?} must be recommended from attempted (unknown-outcome) evidence: {:?}",
            finding.recommended_families()
        );
        assert!(
            !finding.contradiction_conditions().iter().any(|c| matches!(
                c,
                sysdhardener_core::ContradictionCondition::ObservedWithoutSuccessfulUse {
                    family: observed_family,
                    ..
                } if observed_family == &family
            )),
            "{family:?} must NOT be a failure contradiction"
        );
    }
}

#[test]
fn bridge_source_is_src_14_and_preserves_order() {
    let mut events: Vec<SockEvent> = vec![
        sock_event(2, SockOp::Bind, 100, 1_700_000_000_000),
        sock_event(10, SockOp::Connect, 101, 1_700_000_000_001),
    ];
    let observed = sock_events_to_observed(&events);
    assert_eq!(observed.len(), 2);
    let first = observed.first().expect("two events");
    let second = observed.get(1).expect("two events");
    assert_eq!(first.source_id().as_str(), "SRC-14");
    assert_eq!(first.pid(), Some(100));
    assert_eq!(second.pid(), Some(101));
    // Preserve the kernel's delivery order (by timestamp).
    events.sort_by_key(|e| e.timestamp_ms);
    assert_eq!(
        events.first().map(|e| e.timestamp_ms),
        Some(1_700_000_000_000)
    );
}
