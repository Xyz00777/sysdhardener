//! Long-running target for the signal-forwarding test.
//!
//! The target opens an `AF_INET` socket, then sleeps forever. The
//! observer test sends it `SIGTERM` (as systemd would on
//! `systemctl stop`) and asserts the observer forwards the signal,
//! the target dies, and the observer returns the captured events.

#![allow(
    clippy::expect_used,
    reason = "test target asserts its own syscalls succeed; a failure here means the test environment is broken"
)]

use std::time::Duration;

fn main() {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("inet bind must succeed");
    drop(tcp);
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(100));
    }
}
