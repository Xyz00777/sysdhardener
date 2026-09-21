//! Test target: executes a fixed sequence of address-family syscalls
//! so the observer can be verified against real kernel behavior.
//!
//! The target exercises every family the engine models:
//! - `socket(AF_UNIX)` + `bind` + `connect` (success)
//! - `socket(AF_INET)` + `bind` (success)
//! - `socket(AF_INET6)` + `bind` (success)
//! - `socket(AF_NETLINK)` (success)
//! - `socket(AF_PACKET)` (success)
//! - `socket(AF_INET)` with an invalid type (failure — the engine
//!   must record the failed attempt, not treat it as use)
//!
//! The target is built only under the `test-target` feature so
//! production builds never ship it. The raw `libc::socket` calls are
//! the point of the target: they must be real syscalls, not Rust
//! std wrappers, so the observer sees the exact kernel behavior.

#![allow(
    clippy::expect_used,
    reason = "test target asserts its own syscalls succeed; a failure here means the test environment is broken"
)]

use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

fn main() {
    // AF_UNIX: bind a listener, then connect a stream to it.
    let dir = std::env::temp_dir();
    let sock_path = dir.join(format!("sysdhardener-target-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).expect("unix bind must succeed");
    let _stream = UnixStream::connect(&sock_path).expect("unix connect must succeed");
    drop(listener);
    let _ = std::fs::remove_file(&sock_path);

    // AF_INET: bind a TCP socket to loopback.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").expect("inet bind must succeed");
    drop(tcp);

    // AF_INET6: bind a TCP socket to IPv6 loopback.
    let tcp6 = std::net::TcpListener::bind("[::1]:0").expect("inet6 bind must succeed");
    drop(tcp6);

    // AF_NETLINK: open a netlink socket (route link).
    let netlink = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if netlink >= 0 {
        unsafe {
            libc::close(netlink);
        }
    }

    // AF_PACKET: open a raw packet socket (may fail without CAP_NET_RAW;
    // the observer records whichever outcome the kernel returns).
    let packet = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if packet >= 0 {
        unsafe {
            libc::close(packet);
        }
    }

    // Deliberate failure: socket with an invalid type must return -1.
    let bad = unsafe { libc::socket(libc::AF_INET, 0x7fff_ffff, 0) };
    assert!(bad < 0, "invalid socket type must fail");

    // accept: listen on a unix socket and accept a connection.
    let dir2 = std::env::temp_dir();
    let accept_path = dir2.join(format!("sysdhardener-accept-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&accept_path);
    let listener2 = std::os::unix::net::UnixListener::bind(&accept_path)
        .expect("unix listener must bind for accept");
    let _stream2 = std::os::unix::net::UnixStream::connect(&accept_path)
        .expect("unix connect must succeed for accept");
    listener2
        .accept()
        .expect("accept must succeed on the unix listener");
    drop(listener2);
    let _ = std::fs::remove_file(&accept_path);

    // sendto / recvfrom: a UDP pair exchanging a datagram.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp bind must succeed");
    let udp_addr = udp.local_addr().expect("udp local addr");
    let udp_peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp peer bind");
    udp_peer
        .send_to(b"hello", udp_addr)
        .expect("udp sendto must succeed");
    let mut buf = [0u8; 8];
    udp.recv_from(&mut buf).expect("udp recvfrom must succeed");
    drop(udp);
    drop(udp_peer);

    // getsockname / getpeername on a connected pair.
    let listener3 = std::net::TcpListener::bind("127.0.0.1:0").expect("listener bind");
    let laddr = listener3.local_addr().expect("listener local addr");
    let _conn = std::net::TcpStream::connect(laddr).expect("connect for peer addr");
    let (conn2, _) = listener3.accept().expect("accept for peer addr");
    let _ = conn2.local_addr().expect("getsockname (local_addr)");
    let _ = conn2.peer_addr().expect("getpeername (peer_addr)");
    drop(listener3);
    drop(conn2);

    // Fork a child that also exercises a socket, proving the
    // observer follows the whole process tree (the child's syscalls
    // must be captured too).
    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork must succeed");
    if child == 0 {
        // Child: open an AF_INET6 socket and exit.
        let s = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if s >= 0 {
            unsafe {
                libc::close(s);
            }
        }
        unsafe {
            libc::_exit(0);
        }
    }
    // Parent: wait for the child.
    let mut status: libc::c_int = 0;
    let status_ptr: *mut libc::c_int = std::ptr::addr_of_mut!(status);
    unsafe {
        libc::waitpid(child, status_ptr, 0);
    }
}
