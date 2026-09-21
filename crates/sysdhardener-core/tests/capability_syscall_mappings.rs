//! Integration test verifying capability mapping and ambient safety for
//! extended capability-gated syscalls: credentials, memory locking, terminal control,
//! resource limits, I/O scheduling, and process descriptors.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use direct assertions"
)]

use sysdhardener_core::{
    AddressFamily, EventOutcome, FixtureTimestamp, LinuxCapability, ObservedEvent, SourceId,
    recommend_ambient_capabilities, recommend_capability_bounding_set, syscall_to_capabilities,
    syscall_to_inherent_capabilities,
};

fn make_cap_event(syscall: &'static str, outcome: EventOutcome) -> ObservedEvent {
    ObservedEvent::new(
        SourceId::from_static("SRC-12"),
        format!("test-{syscall}"),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Other("capability"),
        outcome,
        format!("{syscall} family=capability ret=0"),
    )
}

#[test]
fn extended_syscalls_map_to_correct_capabilities() {
    let cases = [
        ("setfsuid", &[LinuxCapability::Setuid][..]),
        ("setfsgid", &[LinuxCapability::Setgid][..]),
        ("vhangup", &[LinuxCapability::SysTtyConfig][..]),
        ("mlock2", &[LinuxCapability::IpcLock][..]),
        ("pidfd_send_signal", &[LinuxCapability::Kill][..]),
        ("prlimit64", &[LinuxCapability::SysResource][..]),
        ("ioprio_set", &[LinuxCapability::SysNice][..]),
        ("open_by_handle_at", &[LinuxCapability::DacReadSearch][..]),
        ("pidfd_getfd", &[LinuxCapability::SysPtrace][..]),
        (
            "removexattr",
            &[
                LinuxCapability::Setfcap,
                LinuxCapability::MacOverride,
                LinuxCapability::MacAdmin,
            ][..],
        ),
        (
            "lremovexattr",
            &[
                LinuxCapability::Setfcap,
                LinuxCapability::MacOverride,
                LinuxCapability::MacAdmin,
            ][..],
        ),
        (
            "fremovexattr",
            &[
                LinuxCapability::Setfcap,
                LinuxCapability::MacOverride,
                LinuxCapability::MacAdmin,
            ][..],
        ),
        ("io_uring_register", &[LinuxCapability::SysAdmin][..]),
    ];

    for (syscall, expected) in cases {
        assert_eq!(
            syscall_to_capabilities(syscall),
            expected,
            "syscall {syscall} did not map to expected capabilities"
        );
    }
}

#[test]
fn inherent_gated_syscalls_map_inherently() {
    assert_eq!(
        syscall_to_inherent_capabilities("vhangup"),
        &[LinuxCapability::SysTtyConfig]
    );
    assert_eq!(
        syscall_to_inherent_capabilities("open_by_handle_at"),
        &[LinuxCapability::DacReadSearch]
    );
    for non_inherent in [
        "setfsuid",
        "setfsgid",
        "mlock2",
        "pidfd_send_signal",
        "prlimit64",
        "ioprio_set",
        "pidfd_getfd",
    ] {
        assert_eq!(
            syscall_to_inherent_capabilities(non_inherent),
            &[],
            "{non_inherent} should not be in inherent capabilities"
        );
    }
}

#[test]
fn inherent_syscalls_grant_ambient_capabilities() {
    let events = vec![
        make_cap_event("vhangup", EventOutcome::Success),
        make_cap_event("open_by_handle_at", EventOutcome::Success),
    ];
    let ambient = recommend_ambient_capabilities(&events);
    assert!(ambient.contains(&LinuxCapability::SysTtyConfig));
    assert!(ambient.contains(&LinuxCapability::DacReadSearch));
}

#[test]
fn non_inherent_extended_syscalls_do_not_grant_ambient_capabilities() {
    let events = vec![
        make_cap_event("setfsuid", EventOutcome::Success),
        make_cap_event("setfsgid", EventOutcome::Success),
        make_cap_event("mlock2", EventOutcome::Success),
        make_cap_event("pidfd_send_signal", EventOutcome::Success),
        make_cap_event("prlimit64", EventOutcome::Success),
        make_cap_event("ioprio_set", EventOutcome::Success),
        make_cap_event("pidfd_getfd", EventOutcome::Success),
    ];
    let ambient = recommend_ambient_capabilities(&events);
    assert!(
        ambient.is_empty(),
        "non-inherent syscalls must not grant ambient caps"
    );
}

#[test]
fn extended_syscalls_preserve_capabilities_in_bounding_set() {
    let events = vec![
        make_cap_event("setfsuid", EventOutcome::Success),
        make_cap_event("setfsgid", EventOutcome::Success),
        make_cap_event("vhangup", EventOutcome::Success),
        make_cap_event("mlock2", EventOutcome::Success),
        make_cap_event("pidfd_send_signal", EventOutcome::Success),
        make_cap_event("prlimit64", EventOutcome::Success),
        make_cap_event("ioprio_set", EventOutcome::Success),
        make_cap_event("open_by_handle_at", EventOutcome::Success),
        make_cap_event("pidfd_getfd", EventOutcome::Success),
    ];
    let drop_caps = recommend_capability_bounding_set(&events);

    let preserved = [
        LinuxCapability::Setuid,
        LinuxCapability::Setgid,
        LinuxCapability::SysTtyConfig,
        LinuxCapability::IpcLock,
        LinuxCapability::Kill,
        LinuxCapability::SysResource,
        LinuxCapability::SysNice,
        LinuxCapability::DacReadSearch,
        LinuxCapability::SysPtrace,
    ];

    for cap in preserved {
        assert!(
            !drop_caps.contains(&cap),
            "{cap:?} must be preserved in bounding set when corresponding syscall observed"
        );
    }
}

#[test]
fn capability_finding_source_ids_ignore_non_capability_events() {
    let non_cap_event = ObservedEvent::new(
        SourceId::from_static("SRC-01"),
        "net-event".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Unix,
        EventOutcome::Success,
        "connect family=AF_UNIX ret=0".to_string(),
    );
    let cap_event = ObservedEvent::new(
        SourceId::from_static("SRC-14"),
        "cap-event".to_string(),
        FixtureTimestamp::from_raw_checked(105),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "mount family=capability ret=0".to_string(),
    );

    let compat = sysdhardener_core::RestrictAddressFamilies::record();
    let loss = {
        let fixture = sysdhardener_core::Fixture::from_events(vec![]);
        sysdhardener_core::run_analysis_from_fixture(
            &fixture,
            sysdhardener_core::Capability::ExpectedRoot,
            &compat,
            10,
            None,
            &[],
        )
        .unwrap()
        .finding
        .event_loss()
    };

    let finding_mixed = sysdhardener_core::recommend_ambient_capabilities_finding(
        &[non_cap_event.clone(), cap_event],
        sysdhardener_core::CoverageQuality::Complete,
        loss,
        &compat,
    );
    assert_eq!(finding_mixed.source_ids(), vec!["SRC-14"]);

    let finding_non_cap = sysdhardener_core::recommend_capability_bounding_set_finding(
        &[non_cap_event],
        sysdhardener_core::CoverageQuality::Complete,
        loss,
        &compat,
    );
    assert_eq!(finding_non_cap.source_ids(), vec!["SRC-12"]);
}

#[test]
fn ebpf_unknown_outcome_preserves_capabilities() {
    let events = [
        make_cap_event("mlock2", EventOutcome::Unknown),
        ObservedEvent::new(
            SourceId::from_static("SRC-14"),
            "ebpf-packet".to_owned(),
            FixtureTimestamp::from_raw_checked(100),
            AddressFamily::Packet,
            EventOutcome::Unknown,
            "ebpf op=connect family=Packet".to_owned(),
        ),
    ];
    let drop_caps = recommend_capability_bounding_set(&events);
    assert!(!drop_caps.contains(&LinuxCapability::IpcLock));
    assert!(!drop_caps.contains(&LinuxCapability::NetRaw));
    assert!(!drop_caps.contains(&LinuxCapability::NetAdmin));

    let err_events = [make_cap_event("mlock2", EventOutcome::Error)];
    let drop_err = recommend_capability_bounding_set(&err_events);
    assert!(drop_err.contains(&LinuxCapability::IpcLock));
}
