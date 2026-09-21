//! Integration tests for bounded attach and clean detach semantics.
//!
//! Locked invariants:
//! 1. `observe_pid_with_duration` with a duration window captures syscalls
//!    and returns cleanly when the duration elapses, detaching from the target.
//! 2. The attached target process is not killed and continues running after
//!    detach.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use direct assertions"
)]

use std::process::Command;
use std::time::{Duration, Instant};

use sysdhardener_observer::observe_pid_with_duration;

fn target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_repeating_target"))
}

#[test]
fn attach_with_duration_detaches_and_leaves_target_running() {
    let mut target = Command::new(target_binary())
        .spawn()
        .expect("target must spawn");
    std::thread::sleep(Duration::from_millis(200));

    let pid = i32::try_from(target.id()).expect("target pid fits in i32");
    let start = Instant::now();
    let events =
        observe_pid_with_duration(pid, Some(600)).expect("attach with duration must succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_millis(500),
        "attach must observe for approximately the duration window, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(2500),
        "attach must not block until target exits (3s), took {elapsed:?}"
    );
    assert!(
        !events.is_empty(),
        "attached observer must capture events during window"
    );

    // Target should still be running immediately after detach.
    let try_status = target.try_wait().expect("try_wait");
    assert!(
        try_status.is_none(),
        "target must still be running after tracer detached"
    );

    // Wait for target to exit normally.
    let status = target.wait().expect("target wait");
    assert!(
        status.success(),
        "target must exit successfully on its own, got {status:?}"
    );
}

fn sleepy_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_sleepy_target"))
}

#[test]
fn attach_with_duration_to_idle_target_detaches_promptly() {
    let mut target = Command::new(sleepy_binary())
        .spawn()
        .expect("sleepy target must spawn");
    std::thread::sleep(Duration::from_millis(200));

    let pid = i32::try_from(target.id()).expect("target pid fits in i32");
    let start = Instant::now();
    let events_res = observe_pid_with_duration(pid, Some(300));
    let elapsed = start.elapsed();

    let _ = target.kill();
    let _ = target.wait();

    let _events = events_res.expect("attach to idle target with duration must succeed");
    assert!(
        elapsed >= Duration::from_millis(200),
        "attach must observe for approximately the duration window, took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "attach must not hang on idle target, took {elapsed:?}"
    );
}
