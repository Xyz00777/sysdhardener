//! Tests verifying observer behavior under execve and syscalls returning -ENOSYS.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use assertions"
)]

use std::path::PathBuf;
use std::process::Command;
use sysdhardener_core::{AddressFamily, EventOutcome, ObservedEvent};
use sysdhardener_observer::observe_command;

fn exec_target_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_exec_target"))
}

#[test]
fn observer_handles_child_execve_and_enosys() {
    let mut cmd = Command::new(exec_target_binary());
    let events = observe_command(&mut cmd).expect("observe_command must succeed");

    let parent_v4_events: Vec<&ObservedEvent> = events
        .iter()
        .filter(|e| e.address_family() == AddressFamily::Inet)
        .collect();

    assert!(
        !parent_v4_events.is_empty(),
        "socket(AF_INET) after -ENOSYS and child exec must be captured; got events: {events:?}"
    );
    assert_eq!(
        parent_v4_events.first().map(|e| e.outcome()),
        Some(EventOutcome::Success),
        "socket(AF_INET) must have Success outcome"
    );

    let child_v6_events: Vec<&ObservedEvent> = events
        .iter()
        .filter(|e| e.address_family() == AddressFamily::Inet6)
        .collect();
    assert!(
        !child_v6_events.is_empty(),
        "child socket(AF_INET6) after execve must be captured; got events: {events:?}"
    );
    assert_eq!(
        child_v6_events.first().map(|e| e.outcome()),
        Some(EventOutcome::Success),
        "child socket(AF_INET6) after execve must have Success outcome"
    );
}
