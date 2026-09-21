//! Integration test: raw socket calls (type=raw) must be detected as capability evidence
//! so that `CAP_NET_RAW` and `CAP_NET_ADMIN` are preserved and added to `AmbientCapabilities`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test assertions"
)]

use sysdhardener_core::{
    AddressFamily, Capability, EventOutcome, Fixture, FixtureTimestamp, LinuxCapability,
    ObservedEvent, RestrictAddressFamilies, SourceId, is_capability_event,
    run_analysis_from_fixture,
};

#[test]
fn raw_socket_event_is_identified_as_capability_evidence() {
    let raw_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-raw-1".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Inet,
        EventOutcome::Success,
        "socket family=AF_INET ret=3 type=raw".to_string(),
    );
    assert!(is_capability_event(&raw_sock));

    let non_raw_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-stream-1".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Inet,
        EventOutcome::Success,
        "socket family=AF_INET ret=3 type=stream".to_string(),
    );
    assert!(!is_capability_event(&non_raw_sock));

    let non_cap_other = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-other-1".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "fs family=capability ret=0 path=/var/log/app.log write=true".to_string(),
    );
    assert!(!is_capability_event(&non_cap_other));
}

#[test]
fn raw_socket_in_fixture_preserves_net_raw_and_net_admin() {
    let raw_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-001".to_string(),
        FixtureTimestamp::from_raw_checked(1_700_000_000_000),
        AddressFamily::Inet,
        EventOutcome::Success,
        "socket family=AF_INET ret=3 type=raw".to_string(),
    );
    let cap_event = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-002".to_string(),
        FixtureTimestamp::from_raw_checked(1_700_000_001_000),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "setuid family=capability ret=0".to_string(),
    );
    let fixture = Fixture::from_events(vec![raw_sock, cap_event]);
    let compat = RestrictAddressFamilies::record();
    let summary =
        run_analysis_from_fixture(&fixture, Capability::ExpectedRoot, &compat, 100, None, &[])
            .expect("analysis runs");

    let ambient = summary
        .findings
        .iter()
        .find(|f| f.directive() == "AmbientCapabilities");
    assert!(ambient.is_some(), "ambient finding should be present");
    let ambient = ambient.unwrap();
    assert!(
        ambient
            .recommended_capabilities()
            .contains(&LinuxCapability::NetRaw)
    );
    assert!(
        ambient
            .recommended_capabilities()
            .contains(&LinuxCapability::NetAdmin)
    );

    let bounding = summary
        .findings
        .iter()
        .find(|f| f.directive() == "CapabilityBoundingSet");
    assert!(bounding.is_some(), "bounding finding should be present");
    let bounding = bounding.unwrap();
    // Bounding set recommended_capabilities contains the dropped capabilities (~CAP_X).
    // It must NOT drop CAP_NET_RAW or CAP_NET_ADMIN!
    assert!(
        !bounding
            .recommended_capabilities()
            .contains(&LinuxCapability::NetRaw),
        "CAP_NET_RAW must not be dropped"
    );
    assert!(
        !bounding
            .recommended_capabilities()
            .contains(&LinuxCapability::NetAdmin),
        "CAP_NET_ADMIN must not be dropped"
    );

    assert_eq!(
        ambient.event_loss().seen_events(),
        2,
        "ambient finding must preserve seen_events"
    );
    assert_eq!(
        bounding.event_loss().seen_events(),
        2,
        "bounding set finding must preserve seen_events"
    );
}

#[test]
fn raw_socket_only_fixture_produces_capability_findings() {
    let raw_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-001".to_string(),
        FixtureTimestamp::from_raw_checked(1_700_000_000_000),
        AddressFamily::Inet,
        EventOutcome::Success,
        "socket family=AF_INET ret=3 type=raw".to_string(),
    );
    let fixture = Fixture::from_events(vec![raw_sock]);
    let compat = RestrictAddressFamilies::record();
    let summary =
        run_analysis_from_fixture(&fixture, Capability::ExpectedRoot, &compat, 100, None, &[])
            .expect("analysis runs");

    let ambient = summary
        .findings
        .iter()
        .find(|f| f.directive() == "AmbientCapabilities");
    assert!(
        ambient.is_some(),
        "ambient finding should be present when only raw socket is used"
    );

    let bounding = summary
        .findings
        .iter()
        .find(|f| f.directive() == "CapabilityBoundingSet");
    assert!(
        bounding.is_some(),
        "bounding finding should be present when only raw socket is used"
    );
}

#[test]
fn af_packet_socket_event_is_identified_as_capability_evidence() {
    let packet_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-packet-1".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Packet,
        EventOutcome::Success,
        "socket family=AF_PACKET ret=3 type=dgram".to_string(),
    );
    assert!(is_capability_event(&packet_sock));
}

#[test]
fn af_packet_in_fixture_preserves_net_raw_and_net_admin() {
    let packet_sock = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "evt-001".to_string(),
        FixtureTimestamp::from_raw_checked(1_700_000_000_000),
        AddressFamily::Packet,
        EventOutcome::Success,
        "socket family=AF_PACKET ret=3 type=dgram".to_string(),
    );
    let fixture = Fixture::from_events(vec![packet_sock]);
    let compat = RestrictAddressFamilies::record();
    let summary =
        run_analysis_from_fixture(&fixture, Capability::ExpectedRoot, &compat, 100, None, &[])
            .expect("analysis runs");

    let ambient = summary
        .findings
        .iter()
        .find(|f| f.directive() == "AmbientCapabilities");
    assert!(ambient.is_some(), "ambient finding should be present");
    let ambient = ambient.unwrap();
    assert!(
        ambient
            .recommended_capabilities()
            .contains(&LinuxCapability::NetRaw)
    );
    assert!(
        ambient
            .recommended_capabilities()
            .contains(&LinuxCapability::NetAdmin)
    );
}
