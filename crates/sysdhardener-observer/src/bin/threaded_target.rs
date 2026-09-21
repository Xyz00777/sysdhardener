//! Multi-threaded repeating target for attach tests.
//!
//! Spawns worker threads that perform network syscalls while the main
//! thread sleeps, verifying that attaching to an already-running multi-threaded
//! daemon attaches to all existing threads.

#![allow(clippy::expect_used, reason = "test binary assertions")]

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r1 = Arc::clone(&running);

    let handle = std::thread::spawn(move || {
        while r1.load(Ordering::SeqCst) {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("udp bind must succeed");
            drop(udp);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });

    // Main thread does NOT make network syscalls; it only sleeps.
    std::thread::sleep(std::time::Duration::from_millis(2500));
    running.store(false, Ordering::SeqCst);
    let _ = handle.join();
}
