//! End-to-end observer test: run the real syscall target under the
//! ptrace observer, feed the captured events through the analysis
//! engine, and verify the engine recognizes the exercised families
//! and outcomes correctly.
//!
//! This is the test the user asked for: a real program executing real
//! syscall combinations, verified end to end. The hand-written JSON
//! fixtures remain as deterministic unit inputs; this test proves the
//! live path produces the same typed evidence.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::process::Command;

use sysdhardener_core::{
    AddressFamily, Capability, EventOutcome, ObservedEvent, RestrictAddressFamilies,
    aggregate_address_family_evidence, recommend_restrict_address_families,
};
use sysdhardener_observer::observe_command;

/// Path to the syscall target binary (built by Cargo for the test
/// when the `test-target` feature is enabled).
fn target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_syscall_target"))
}

#[test]
fn observer_captures_real_syscalls_and_engine_recognizes_families() {
    let mut command = Command::new(target_binary());
    let events = observe_command(&mut command).expect("observer must capture the target");

    // The target exercises unix, inet, inet6, netlink, packet, and a
    // deliberate failure. The observer must have seen at least the
    // three families the engine models as the recommendation set.
    let families: Vec<AddressFamily> = events.iter().map(ObservedEvent::address_family).collect();
    assert!(
        families.contains(&AddressFamily::Unix),
        "observer must capture AF_UNIX; got {families:?}"
    );
    assert!(
        families.contains(&AddressFamily::Inet),
        "observer must capture AF_INET; got {families:?}"
    );
    assert!(
        families.contains(&AddressFamily::Inet6),
        "observer must capture AF_INET6; got {families:?}"
    );

    // The deliberate failure (invalid socket type) must be recorded
    // as an Error outcome, not as successful use.
    let failed: usize = events
        .iter()
        .filter(|e| e.outcome() == EventOutcome::Error)
        .count();
    assert!(
        failed > 0,
        "the deliberate failing socket must be captured as an Error outcome"
    );

    // Feed the captured events through the engine: aggregate, then
    // recommend. The engine must accept the live evidence and derive
    // the same provisional candidate shape as from fixtures.
    let fixture = sysdhardener_core::Fixture::from_events(events);
    let bundle = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("live evidence must aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("live evidence must produce a candidate");

    // The recommendation must include the families with successful
    // use (unix, inet, inet6) and exclude nothing observed.
    let recommended: Vec<AddressFamily> = finding.recommended_families().to_vec();
    assert!(
        recommended.contains(&AddressFamily::Unix),
        "unix must be recommended after successful use; got {recommended:?}"
    );
    assert!(
        recommended.contains(&AddressFamily::Inet),
        "inet must be recommended after successful use; got {recommended:?}"
    );
    assert!(
        recommended.contains(&AddressFamily::Inet6),
        "inet6 must be recommended after successful use; got {recommended:?}"
    );
}

#[test]
fn observer_follows_forked_children_of_the_target() {
    // The syscall target forks a child that opens an AF_INET6 socket.
    // The observer must capture the child's syscalls too — the whole
    // process tree, not just the direct child.
    let mut command = Command::new(target_binary());
    let events = observe_command(&mut command).expect("observer must capture the target");

    // The child's AF_INET6 socket must appear in the captured stream.
    // The parent also opens AF_INET6, so count: the child adds one
    // more socket(AF_INET6) than the parent alone would produce.
    let inet6_sockets: usize = events
        .iter()
        .filter(|e| {
            e.address_family() == AddressFamily::Inet6
                && e.args().contains("socket")
                && e.outcome() == EventOutcome::Success
        })
        .count();
    assert!(
        inet6_sockets >= 2,
        "the forked child's AF_INET6 socket must be captured (parent + child = 2+), got {inet6_sockets}"
    );

    // At least two distinct pids must be present in the stream: the
    // parent and the forked child.
    let pids: std::collections::BTreeSet<i32> =
        events.iter().filter_map(ObservedEvent::pid).collect();
    assert!(
        pids.len() >= 2,
        "whole-tree observation must attribute events to 2+ processes, got {pids:?}"
    );
}

#[test]
fn observer_captures_all_socket_syscalls_the_kernel_delivers() {
    let mut command = Command::new(target_binary());
    let events = observe_command(&mut command).expect("observer must capture the target");

    // The decoder knows 8 socket-family syscalls. The kernel
    // delivers ptrace stops for 7 of them on this kernel
    // (socket/connect/bind/accept/sendto/recvfrom/getsockname).
    // `getpeername` executes in the target but its syscall stops are
    // not delivered to a PTRACE_SYSCALL loop on this xanmod kernel —
    // a documented observation gap (backlog E-04 and
    // docs/research.md), not a decoder bug.
    // Delivery is kernel-dependent: another kernel may deliver all
    // syscall stops.
    for syscall in [
        "socket",
        "connect",
        "bind",
        "accept",
        "sendto",
        "recvfrom",
        "getsockname",
    ] {
        assert!(
            events.iter().any(|e| e.args().starts_with(syscall)),
            "the observer must capture the {syscall} syscall; got {} events",
            events.len()
        );
    }
}

#[test]
fn observer_follows_the_process_tree_across_daemonization() {
    // A daemonizing service (like nginx in default mode) double-forks:
    // the process the observer spawned exits, and a grandchild
    // survives. The observer must still capture the grandchild's
    // syscalls.
    let mut command = Command::new(daemon_target_binary());
    let events = observe_command(&mut command).expect("observer must capture the daemonized tree");

    assert!(
        events
            .iter()
            .any(|e| e.address_family() == AddressFamily::Inet && e.args().contains("bind")),
        "the daemonized grandchild's AF_INET bind must be captured"
    );
}

/// Path to the daemon-style target binary.
fn daemon_target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_daemon_target"))
}

#[test]
fn observer_captures_capability_relevant_syscalls() {
    // The capability target exercises the capability-gated syscalls
    // from the capability map Part 2. The observer must capture them
    // as `Other("capability")` events (capability evidence, not
    // address-family evidence).
    let mut command = Command::new(capability_target_binary());
    let events = observe_command(&mut command).expect("observer must capture the target");

    let capability_count: usize = events
        .iter()
        .filter(|e| e.address_family() == AddressFamily::Other("capability"))
        .count();
    assert!(
        capability_count > 0,
        "the observer must capture capability-relevant syscalls"
    );

    #[cfg(target_arch = "x86_64")]
    let expected_failed = ["mount", "chroot", "setns", "reboot", "iopl"];
    #[cfg(not(target_arch = "x86_64"))]
    let expected_failed = ["mount", "chroot", "setns", "reboot"];
    for syscall in expected_failed {
        assert!(
            events
                .iter()
                .any(|e| { e.args().starts_with(syscall) && e.outcome() == EventOutcome::Error }),
            "the {syscall} syscall must be captured as an EPERM failure"
        );
    }

    // The recommendation must NOT include the capability events: they
    // are `Other` families, excluded from the RestrictAddressFamilies=
    // allow-list.
    let fixture = sysdhardener_core::Fixture::from_events(events);
    let bundle = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("live evidence must aggregate");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("live evidence must produce a candidate");
    assert!(
        !finding
            .recommended_families()
            .iter()
            .any(|f| matches!(f, AddressFamily::Other(_))),
        "capability events must never enter the RestrictAddressFamilies= allow-list"
    );
}

/// Path to the capability-relevant target binary.
fn capability_target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_capability_target"))
}
