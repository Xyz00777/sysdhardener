//! Verification of clean signal forwarding and exit on SIGTERM.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions"
)]

use std::process::Command;
use sysdhardener_observer::observe_command;

#[test]
fn spawned_target_interrupted_with_sigterm_exits_cleanly() {
    let target_path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_sleepy_target"));
    let mut cmd = Command::new(target_path);

    let handle = std::thread::spawn(move || observe_command(&mut cmd));

    std::thread::sleep(std::time::Duration::from_millis(300));
    for _ in 0..50 {
        if handle.is_finished() {
            break;
        }
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTERM);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let result = handle.join().expect("thread join");
    assert!(
        result.is_ok(),
        "observe_command must return Ok on forwarded SIGTERM; got {result:?}"
    );
    let events = result.unwrap();
    assert!(
        events.iter().any(|e| e.args().contains("family=inet")),
        "must capture inet event before SIGTERM"
    );
}
