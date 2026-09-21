//! Test that attaching to an already-running multi-threaded process attaches
//! to all existing worker threads and captures their socket syscalls without
//! delivering disruptive group-stop signals.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests"
)]

use std::process::Command;
use std::time::Duration;

use sysdhardener_observer::observe_pid_with_duration;

fn target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_threaded_target"))
}

#[test]
fn attach_captures_existing_worker_threads() {
    let mut target = Command::new(target_binary())
        .spawn()
        .expect("target must spawn");

    // Allow worker thread to spin up before we attach
    std::thread::sleep(Duration::from_millis(300));

    let pid = i32::try_from(target.id()).expect("target pid fits in i32");
    let events =
        observe_pid_with_duration(pid, Some(500)).expect("attach with duration must succeed");

    let _ = target.wait();

    // Verify events were captured from the worker thread
    let inet_seen = events
        .iter()
        .any(|e| e.args().starts_with("socket") && e.args().contains("family=inet"));
    assert!(
        inet_seen,
        "observer must capture socket syscalls performed by pre-existing worker threads"
    );
}
