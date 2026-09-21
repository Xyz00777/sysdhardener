//! Contract test: `AmbientCapabilities` must never grant root bypass
//! capabilities (`CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_IPC_LOCK`)
//! merely because a service performed normal unprivileged file/memory syscalls.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions"
)]

use sysdhardener_core::{
    AddressFamily, EventOutcome, FixtureTimestamp, LinuxCapability, ObservedEvent, SourceId,
    recommend_ambient_capabilities,
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
fn unprivileged_file_and_memory_syscalls_do_not_grant_dangerous_ambient_caps() {
    let events = vec![
        make_cap_event("openat", EventOutcome::Success),
        make_cap_event("open", EventOutcome::Success),
        make_cap_event("creat", EventOutcome::Success),
        make_cap_event("readlink", EventOutcome::Success),
        make_cap_event("access", EventOutcome::Success),
        make_cap_event("mmap", EventOutcome::Success),
        make_cap_event("chmod", EventOutcome::Success),
        make_cap_event("kill", EventOutcome::Success),
        make_cap_event("timerfd_create", EventOutcome::Success),
    ];

    let ambient = recommend_ambient_capabilities(&events);

    assert!(
        !ambient.contains(&LinuxCapability::DacOverride),
        "AmbientCapabilities must not grant CAP_DAC_OVERRIDE for standard openat"
    );
    assert!(
        !ambient.contains(&LinuxCapability::DacReadSearch),
        "AmbientCapabilities must not grant CAP_DAC_READ_SEARCH for standard openat"
    );
    assert!(
        !ambient.contains(&LinuxCapability::IpcLock),
        "AmbientCapabilities must not grant CAP_IPC_LOCK for standard mmap"
    );
    assert!(
        !ambient.contains(&LinuxCapability::Fowner),
        "AmbientCapabilities must not grant CAP_FOWNER for standard chmod"
    );
    assert!(
        !ambient.contains(&LinuxCapability::Kill),
        "AmbientCapabilities must not grant CAP_KILL for standard kill"
    );
    assert!(
        !ambient.contains(&LinuxCapability::WakeAlarm),
        "AmbientCapabilities must not grant CAP_WAKE_ALARM for standard timerfd_create"
    );
}

#[test]
fn inherently_privileged_syscalls_grant_ambient_caps() {
    let events = vec![
        make_cap_event("mount", EventOutcome::Success),
        make_cap_event("chroot", EventOutcome::Success),
        make_cap_event("setdomainname", EventOutcome::Success),
        make_cap_event("clock_adjtime", EventOutcome::Success),
        make_cap_event("swapoff", EventOutcome::Success),
        make_cap_event("kexec_file_load", EventOutcome::Success),
        make_cap_event("pivot_root", EventOutcome::Success),
    ];

    let ambient = recommend_ambient_capabilities(&events);

    assert!(
        ambient.contains(&LinuxCapability::SysAdmin),
        "mount must grant CAP_SYS_ADMIN"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysChroot),
        "chroot must grant CAP_SYS_CHROOT"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysAdmin),
        "setdomainname must grant CAP_SYS_ADMIN"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysTime),
        "clock_adjtime must grant CAP_SYS_TIME"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysAdmin),
        "swapoff must grant CAP_SYS_ADMIN"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysBoot),
        "kexec_file_load must grant CAP_SYS_BOOT"
    );
    assert!(
        ambient.contains(&LinuxCapability::SysAdmin),
        "pivot_root must grant CAP_SYS_ADMIN"
    );
}

#[test]
fn sched_priority_syscalls_map_to_sys_nice() {
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("sched_setparam"),
        &[LinuxCapability::SysNice]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("sched_setattr"),
        &[LinuxCapability::SysNice]
    );
}

#[test]
fn boot_and_credential_syscalls_map_to_capabilities() {
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("reboot"),
        &[LinuxCapability::SysBoot]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("kexec_load"),
        &[LinuxCapability::SysBoot]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("kexec_file_load"),
        &[LinuxCapability::SysBoot]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("setregid"),
        &[LinuxCapability::Setgid]
    );
}

#[test]
fn reboot_preserves_cap_sys_boot_in_bounding_set() {
    let events = vec![make_cap_event("reboot", EventOutcome::Success)];
    let drop_caps = sysdhardener_core::recommend_capability_bounding_set(&events);
    assert!(
        !drop_caps.contains(&LinuxCapability::SysBoot),
        "reboot must preserve CAP_SYS_BOOT in bounding set"
    );
}

#[test]
fn privileged_admin_and_group_syscalls_grant_ambient_caps() {
    let events = vec![
        make_cap_event("setgroups", EventOutcome::Success),
        make_cap_event("quotactl_fd", EventOutcome::Success),
        make_cap_event("fanotify_init", EventOutcome::Success),
        make_cap_event("fsmount", EventOutcome::Success),
        make_cap_event("lookup_dcookie", EventOutcome::Success),
    ];
    let ambient = recommend_ambient_capabilities(&events);
    assert!(ambient.contains(&LinuxCapability::Setgid));
    assert!(ambient.contains(&LinuxCapability::SysAdmin));
}

#[test]
fn userfaultfd_and_mount_api_map_to_capabilities() {
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("userfaultfd"),
        &[LinuxCapability::SysPtrace]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("quotactl_fd"),
        &[LinuxCapability::SysAdmin]
    );
    assert_eq!(
        sysdhardener_core::syscall_to_capabilities("open_tree"),
        &[LinuxCapability::SysAdmin]
    );
}

#[test]
fn detailed_entry_found_considers_capabilities() {
    let events = vec![make_cap_event("reboot", EventOutcome::Success)];
    let compat = sysdhardener_core::RestrictAddressFamilies::record();
    let finding = sysdhardener_core::recommend_ambient_capabilities_finding(
        &events,
        sysdhardener_core::CoverageQuality::Complete,
        finding_dummy_loss(),
        &compat,
    );
    let detailed = sysdhardener_core::project_detailed(std::slice::from_ref(&finding));
    let entry = detailed.entries().first().unwrap();
    assert_eq!(entry.found(), Some("found"));
}

fn finding_dummy_loss() -> sysdhardener_core::EventLoss {
    let fixture = sysdhardener_core::Fixture::from_events(vec![]);
    let compat = sysdhardener_core::RestrictAddressFamilies::record();
    let summary = sysdhardener_core::run_analysis_from_fixture(
        &fixture,
        sysdhardener_core::Capability::ExpectedRoot,
        &compat,
        10,
        None,
        &[],
    )
    .unwrap();
    summary.finding.event_loss()
}

#[test]
fn capability_finding_preserves_event_source_ids() {
    let event = ObservedEvent::new(
        SourceId::from_static("SRC-14"),
        "ebpf-test".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "mount family=capability ret=0".to_string(),
    );
    let compat = sysdhardener_core::RestrictAddressFamilies::record();
    let finding = sysdhardener_core::recommend_ambient_capabilities_finding(
        &[event],
        sysdhardener_core::CoverageQuality::Complete,
        finding_dummy_loss(),
        &compat,
    );
    assert_eq!(finding.source_ids(), vec!["SRC-14"]);
}
