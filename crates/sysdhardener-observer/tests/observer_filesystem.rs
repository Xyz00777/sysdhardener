//! End-to-end test for ptrace filesystem observation.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::redundant_closure_for_method_calls,
    reason = "integration tests use direct assertions"
)]

use std::process::Command;

use sysdhardener_core::{Capability, Fixture, RestrictAddressFamilies, run_analysis_from_fixture};
use sysdhardener_observer::observe_command;

fn fs_target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_fs_target"))
}

#[test]
fn observer_captures_filesystem_reads_and_writes() {
    let mut command = Command::new(fs_target_binary());
    let events = observe_command(&mut command).expect("observer must capture the target");

    // The observer must capture events with path= and write=
    let has_read_etc = events
        .iter()
        .any(|e| e.args().contains("path=/etc/hosts") && e.args().contains("write=false"));
    assert!(
        has_read_etc,
        "observer must capture read of /etc/hosts; all args: {:?}",
        events.iter().map(|e| e.args()).collect::<Vec<_>>()
    );

    let has_write_tmp = events
        .iter()
        .any(|e| e.args().contains("/tmp/sysdhardener-test-") && e.args().contains("write=true"));
    assert!(has_write_tmp, "observer must capture write to /tmp");

    let has_unlink = events.iter().any(|e| {
        (e.args().starts_with("unlink") || e.args().starts_with("unlinkat"))
            && e.args().contains("/tmp/sysdhardener-test-")
            && e.args().contains("write=true")
    });
    assert!(has_unlink, "observer must capture unlink of temporary file");

    // Run through analysis engine
    let fixture = Fixture::from_events(events);
    let summary = run_analysis_from_fixture(
        &fixture,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
        10,
        None,
        &[],
    )
    .expect("analysis succeeds");

    let directives: Vec<&str> = summary.findings.iter().map(|f| f.directive()).collect();
    assert!(
        directives.contains(&"ProtectSystem"),
        "Must contain ProtectSystem; findings: {directives:?}"
    );
    assert!(
        directives.contains(&"ReadWritePaths"),
        "Must contain ReadWritePaths"
    );
    assert!(
        directives.contains(&"ProtectHome"),
        "Must contain ProtectHome"
    );
    assert!(
        directives.contains(&"ProtectControlGroups"),
        "Must contain ProtectControlGroups"
    );
}
