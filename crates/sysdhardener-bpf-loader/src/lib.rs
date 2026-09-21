//! Loads and attaches the sysdhardener eBPF program.
//!
//! This crate runs on the **root/systemd host** (the reference
//! environment): it loads the compiled `sysdhardener-ebpf` object
//! (built on a nightly-capable host), attaches its cgroup sockaddr
//! programs to a target unit's cgroup, and reads the event ring
//! buffer. It compiles on stable here; loading requires `CAP_BPF` /
//! `CAP_SYS_ADMIN` (root) and a kernel with BPF support.
//!
//! The ring-buffer frame layout is the shared wire contract in
//! `sysdhardener-wire-format` (the same crate the eBPF program
//! depends on), so the two sides can never drift apart.

mod bridge;

use aya::Ebpf;
use aya::maps::RingBuf;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, ProgramError};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};

use sysdhardener_wire_format::{SockEvent, decode};

static STOP_FLAG: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_stop_signal(_sig: libc::c_int) {
    STOP_FLAG.store(true, Ordering::SeqCst);
}

struct SignalGuard {
    old_term: libc::sigaction,
    old_int: libc::sigaction,
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: restore prior SIGTERM and SIGINT handlers using libc FFI.
        unsafe {
            libc::sigaction(
                libc::SIGTERM,
                &raw const self.old_term,
                std::ptr::null_mut(),
            );
            libc::sigaction(libc::SIGINT, &raw const self.old_int, std::ptr::null_mut());
        }
    }
}

#[allow(
    clippy::fn_to_numeric_cast_any,
    reason = "FFI: sigaction.sa_sigaction is sighandler_t; handler cast required by C ABI"
)]
fn install_signal_handlers() -> SignalGuard {
    STOP_FLAG.store(false, Ordering::SeqCst);
    // SAFETY: install process-level signal handlers for clean early detachment on SIGINT/SIGTERM.
    unsafe {
        let mut action: libc::sigaction = libc::sigaction {
            sa_sigaction: handle_stop_signal as *const () as libc::sighandler_t,
            ..std::mem::zeroed()
        };
        libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask));
        let mut old_term: libc::sigaction = std::mem::zeroed();
        let mut old_int: libc::sigaction = std::mem::zeroed();
        libc::sigaction(
            libc::SIGTERM,
            &raw const action,
            std::ptr::addr_of_mut!(old_term),
        );
        libc::sigaction(
            libc::SIGINT,
            &raw const action,
            std::ptr::addr_of_mut!(old_int),
        );
        SignalGuard { old_term, old_int }
    }
}

pub use bridge::{
    EBPF_SOURCE_ID, fs_event_to_observed_with_cgroup, fs_events_to_observed_with_cgroup,
    sock_event_to_observed, sock_event_to_observed_with_cgroup, sock_events_to_observed,
    sock_events_to_observed_with_cgroup,
};

/// Typed failure of the loader.
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    /// The eBPF object could not be loaded.
    #[error("bpf object load failed: {0}")]
    Load(#[from] aya::EbpfError),
    /// A program could not be found or converted.
    #[error("program {0} unavailable: {1}")]
    Program(String, ProgramError),
    /// The program could not be attached to the cgroup.
    #[error("attach to cgroup failed: {0}")]
    Attach(String),
    /// The event ring buffer could not be opened.
    #[error("ring buffer open failed: {0}")]
    RingBuf(String),
}

/// The event-ring map name in the eBPF object.
const EVENT_MAP: &str = "EVENTS";

/// Attach the loaded program to a cgroup and capture events for
/// `duration_ms` milliseconds, returning the decoded events.
///
/// # Errors
/// Returns [`LoaderError`] when the object fails to load, a program
/// cannot be attached, or the ring buffer cannot be opened.
pub fn observe_cgroup_events(
    ebpf_object: &[u8],
    cgroup_fd: &std::fs::File,
    duration_ms: u64,
) -> Result<Vec<SockEvent>, LoaderError> {
    let mut bpf = Ebpf::load(ebpf_object)?;
    attach_all(&mut bpf, cgroup_fd)?;
    let map = bpf
        .map_mut(EVENT_MAP)
        .ok_or_else(|| LoaderError::RingBuf("EVENTS map not found".to_owned()))?;
    let mut ring = RingBuf::try_from(map).map_err(|e| LoaderError::RingBuf(e.to_string()))?;

    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(duration_ms))
        .ok_or_else(|| LoaderError::RingBuf("duration overflow".to_owned()))?;

    let _sig_guard = install_signal_handlers();
    let mut events = Vec::new();
    while std::time::Instant::now() < deadline && !STOP_FLAG.load(Ordering::SeqCst) {
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if let Some(event) = decode(bytes) {
                events.push(event);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    while let Some(item) = ring.next() {
        let bytes: &[u8] = &item;
        if let Some(event) = decode(bytes) {
            events.push(event);
        }
    }
    Ok(events)
}

/// Attach every sockaddr program in the object to the cgroup.
fn attach_all(bpf: &mut Ebpf, cgroup_fd: &std::fs::File) -> Result<(), LoaderError> {
    for name in [
        "bind4", "bind6", "connect4", "connect6", "sendmsg4", "sendmsg6", "recvmsg4", "recvmsg6",
    ] {
        let program: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .ok_or_else(|| LoaderError::Attach(format!("{name} not found")))?
            .try_into()
            .map_err(|e| LoaderError::Program(name.to_owned(), e))?;
        program
            .load()
            .map_err(|e| LoaderError::Program(name.to_owned(), e))?;
        program
            .attach(cgroup_fd.as_fd(), CgroupAttachMode::Single)
            .map_err(|e| LoaderError::Attach(format!("{name}: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysdhardener_wire_format::SockOp;

    #[test]
    fn decodes_event_from_bytes() {
        let mut bytes = [0u8; 24];
        bytes[0..4].copy_from_slice(&2u32.to_ne_bytes()); // pid
        bytes[4..8].copy_from_slice(&10u32.to_ne_bytes()); // AF_INET6
        bytes[8..12].copy_from_slice(&SockOp::Bind.as_u32().to_ne_bytes());
        bytes[16..24].copy_from_slice(&1_700_000_000_000u64.to_ne_bytes());
        let event = decode(&bytes).expect("24-byte frame decodes");
        assert_eq!(event.pid, 2);
        assert_eq!(event.family, 10);
        assert_eq!(event.op, SockOp::Bind.as_u32());
        assert_eq!(event.timestamp_ms, 1_700_000_000_000);
    }
}
