#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

//! sysdhardener eBPF program: capture socket-family evidence per
//! target cgroup.
//!
//! Attached as cgroup sockaddr programs (bind/connect/sendmsg/recvmsg
//! family hooks) on the target unit's cgroup; every socket operation
//! in the unit fires the hook in-kernel, and the event (family,
//! operation, pid) is streamed to user space via a ring buffer. This
//! is the production interposition (deferred doc option 1): the
//! observer is independent of the target's process tree and captures
//! **all** processes in the cgroup, including ones the ptrace
//! observer never attached to.
//!
//! The ring-buffer frame is the shared wire contract in
//! `sysdhardener-wire-format` (the same crate the user-space loader
//! depends on), so the two sides can never drift apart.
//!
//! # Build
//!
//! Requires a nightly toolchain with `asm_experimental_arch` and the
//! `bpfel-unknown-none` target + `bpf-linker`. The workspace's
//! stable CI builds the **loader** (`aya`, stable) and unit-tests the
//! ring decode; this crate is built on a nightly-capable host and
//! loaded on a root/systemd host (the reference environment).

use aya_ebpf::btf_maps::ring_buf::RingBuf;
use aya_ebpf::macros::{btf_map, cgroup_sock_addr};
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::{EbpfContext, helpers::bpf_ktime_get_ns};

use sysdhardener_wire_format::{SockEvent, SockOp};

/// Ring buffer carrying events to the user-space loader.
#[btf_map(name = "EVENTS")]
static mut EVENTS: RingBuf<SockEvent, 256> = RingBuf::new();

#[allow(
    static_mut_refs,
    reason = "eBPF static maps are single-threaded in-kernel; the aya-ebpf btf_map pattern requires a shared reference to the mutable static"
)]
fn emit(ctx: &SockAddrContext, op: SockOp) {
    let family: u32 = unsafe { (*ctx.sock_addr).family };
    let pid: u32 = ctx.pid();
    let now: u64 = unsafe { bpf_ktime_get_ns() } / 1_000_000;
    let event = SockEvent {
        pid,
        family,
        op: op.as_u32(),
        timestamp_ms: now,
    };
    unsafe {
        let _ = EVENTS.output(&event, 0);
    }
}

#[cgroup_sock_addr(bind4)]
fn bind4(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::Bind);
    1
}

#[cgroup_sock_addr(connect4)]
fn connect4(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::Connect);
    1
}

#[cgroup_sock_addr(bind6)]
fn bind6(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::Bind);
    1
}

#[cgroup_sock_addr(connect6)]
fn connect6(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::Connect);
    1
}

#[cgroup_sock_addr(sendmsg4)]
fn sendmsg4(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::SendMsg);
    1
}

#[cgroup_sock_addr(recvmsg4)]
fn recvmsg4(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::RecvMsg);
    1
}

#[cgroup_sock_addr(sendmsg6)]
fn sendmsg6(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::SendMsg);
    1
}

#[cgroup_sock_addr(recvmsg6)]
fn recvmsg6(ctx: SockAddrContext) -> i32 {
    emit(&ctx, SockOp::RecvMsg);
    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("", options(noreturn)) }
}
