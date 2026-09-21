//! Repeating-syscall target for the attach tests.
//!
//! Loops doing `socket(AF_INET)` + `bind` + `close` every 50ms for a
//! bounded duration, so an attached observer (which starts after the
//! target is already running) still captures address-family syscalls.

#![allow(
    clippy::expect_used,
    reason = "test target asserts its own syscalls succeed; a failure here means the test environment is broken"
)]

use std::net::UdpSocket;

fn main() {
    for _ in 0..60 {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("udp bind must succeed");
        drop(udp);
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
