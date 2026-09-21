//! Daemon-style target: double-forks (as a daemonizing service like
//! nginx does in default mode), the original process exits, and the
//! surviving grandchild opens a socket. Proves the observer follows
//! the whole tree across a daemonization boundary.

#![allow(
    clippy::expect_used,
    reason = "test target asserts its own syscalls succeed; a failure here means the test environment is broken"
)]

fn main() {
    // First fork: the intermediate process.
    let pid1 = unsafe { libc::fork() };
    assert!(pid1 >= 0, "first fork must succeed");
    if pid1 > 0 {
        // Original process (the one the observer spawned): wait for
        // the intermediate and exit — this is the daemonization exit
        // systemd's Type=forking waits on.
        let mut status: libc::c_int = 0;
        let status_ptr: *mut libc::c_int = std::ptr::addr_of_mut!(status);
        unsafe {
            libc::waitpid(pid1, status_ptr, 0);
        }
        return;
    }
    // Intermediate process: second fork, then exit.
    let pid2 = unsafe { libc::fork() };
    assert!(pid2 >= 0, "second fork must succeed");
    if pid2 > 0 {
        unsafe {
            libc::_exit(0);
        }
    }
    // Surviving grandchild (the "daemon"): open an AF_INET socket.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("inet bind must succeed");
    drop(tcp);
    std::thread::sleep(std::time::Duration::from_millis(100));
}
