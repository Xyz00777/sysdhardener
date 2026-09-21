//! Shared wire format between the in-kernel eBPF program and the
//! user-space loader.
//!
//! The eBPF program (`crates/sysdhardener-ebpf`) emits one
//! [`SockEvent`] per socket operation into a ring buffer; the loader
//! (`crates/sysdhardener-bpf-loader`) reads the raw bytes and decodes
//! them with [`decode`]. The struct layout is the contract between the
//! two crates — it must be identical in both, so it lives here, in a
//! crate both depend on, instead of being duplicated by hand.
//!
//! This crate is `no_std` (the eBPF program is `no_std`) and has no
//! dependencies, so the eBPF program can link it without pulling any
//! user-space machinery into the kernel image.

#![no_std]
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

/// The socket operation that triggered a cgroup sockaddr hook.
///
/// The numeric tags are the wire values written into the ring buffer;
/// they are stable and must not be renumbered (a future program
/// version may add tags, never reuse them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SockOp {
    /// `bind` — the hook fired on a bind syscall.
    Bind = 1,
    /// `connect` — the hook fired on a connect syscall.
    Connect = 2,
    /// `sendmsg` — the hook fired on a sendmsg syscall.
    SendMsg = 3,
    /// `recvmsg` — the hook fired on a recvmsg syscall.
    RecvMsg = 4,
}

impl SockOp {
    /// The numeric tag written into the ring buffer.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a numeric tag. Returns `None` for unknown values (a
    /// future program version must not break the decoder).
    #[must_use]
    pub const fn from_u32(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Bind),
            2 => Some(Self::Connect),
            3 => Some(Self::SendMsg),
            4 => Some(Self::RecvMsg),
            _ => None,
        }
    }
}

/// One captured socket-family event, shared between the in-kernel
/// eBPF program and the user-space loader.
///
/// The layout is the wire contract: `pid` (4) + `family` (4) + `op`
/// (4) + `timestamp_ms` (8, u64-aligned at offset 16) = 24 bytes. The
/// eBPF program writes this struct into the ring buffer; the loader
/// reads the raw bytes and decodes them with [`decode`].
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockEvent {
    /// PID of the process that made the socket operation.
    pub pid: u32,
    /// `sa_family_t` of the socket (`AF_INET`, `AF_INET6`, ...).
    pub family: u32,
    /// Operation tag: bind/connect/sendmsg/recvmsg.
    pub op: u32,
    /// Kernel timestamp in milliseconds.
    pub timestamp_ms: u64,
}

/// The size of one [`SockEvent`] in bytes (24).
pub const SOCK_EVENT_SIZE: usize = core::mem::size_of::<SockEvent>();

/// The filesystem operation that triggered an eBPF tracepoint/probe hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsOp {
    /// Read access.
    Read = 1,
    /// Write access.
    Write = 2,
}

impl FsOp {
    /// The numeric tag written into the ring buffer.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Decode a numeric tag.
    #[must_use]
    pub const fn from_u32(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            _ => None,
        }
    }
}

/// One captured filesystem event from eBPF.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsEvent {
    /// PID of the process that accessed the path.
    pub pid: u32,
    /// Operation tag: Read=1, Write=2.
    pub op: u32,
    /// Kernel timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Path length in bytes.
    pub path_len: u32,
    /// Path buffer.
    pub path: [u8; 256],
}

/// The size of one [`FsEvent`] in bytes.
pub const FS_EVENT_SIZE: usize = core::mem::size_of::<FsEvent>();

/// Decode a [`SockEvent`] from ring-buffer bytes.
///
/// Returns `None` for a short buffer (never panics; a malformed frame
/// is dropped, not fatal).
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<SockEvent> {
    if bytes.len() < SOCK_EVENT_SIZE {
        return None;
    }
    let pid = u32::from_ne_bytes(bytes.get(0..4)?.try_into().ok()?);
    let family = u32::from_ne_bytes(bytes.get(4..8)?.try_into().ok()?);
    let op = u32::from_ne_bytes(bytes.get(8..12)?.try_into().ok()?);
    let timestamp_ms = u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?);
    Some(SockEvent {
        pid,
        family,
        op,
        timestamp_ms,
    })
}

/// Decode an [`FsEvent`] from ring-buffer bytes.
#[must_use]
pub fn decode_fs(bytes: &[u8]) -> Option<FsEvent> {
    if bytes.len() < FS_EVENT_SIZE {
        return None;
    }
    let pid = u32::from_ne_bytes(bytes.get(0..4)?.try_into().ok()?);
    let op = u32::from_ne_bytes(bytes.get(4..8)?.try_into().ok()?);
    let timestamp_ms = u64::from_ne_bytes(bytes.get(8..16)?.try_into().ok()?);
    let path_len = u32::from_ne_bytes(bytes.get(16..20)?.try_into().ok()?);
    if path_len > 256 {
        return None;
    }
    let mut path = [0u8; 256];
    path.copy_from_slice(bytes.get(20..276)?);
    Some(FsEvent {
        pid,
        op,
        timestamp_ms,
        path_len,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sock_event_layout_is_stable() {
        // pid(4) + family(4) + op(4) + u64-aligned timestamp(8, at
        // offset 16). The eBPF program and the loader both depend on
        // this exact layout; a change here fails the test.
        assert_eq!(SOCK_EVENT_SIZE, 24);
        assert_eq!(core::mem::align_of::<SockEvent>(), 8);
        assert_eq!(core::mem::offset_of!(SockEvent, timestamp_ms), 16);
    }

    #[test]
    fn decodes_event_from_bytes() {
        let mut bytes = [0u8; 24];
        bytes[0..4].copy_from_slice(&2u32.to_ne_bytes()); // pid
        bytes[4..8].copy_from_slice(&10u32.to_ne_bytes()); // AF_INET6
        bytes[8..12].copy_from_slice(&1u32.to_ne_bytes()); // bind
        bytes[16..24].copy_from_slice(&1_700_000_000_000u64.to_ne_bytes());
        let event = decode(&bytes).expect("24-byte frame decodes");
        assert_eq!(event.pid, 2);
        assert_eq!(event.family, 10);
        assert_eq!(event.op, SockOp::Bind.as_u32());
        assert_eq!(event.timestamp_ms, 1_700_000_000_000);
    }

    #[test]
    fn short_frame_is_dropped_not_fatal() {
        assert_eq!(decode(&[0u8; 23]), None);
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn sock_op_tags_round_trip() {
        for op in [
            SockOp::Bind,
            SockOp::Connect,
            SockOp::SendMsg,
            SockOp::RecvMsg,
        ] {
            assert_eq!(SockOp::from_u32(op.as_u32()), Some(op));
        }
        assert_eq!(SockOp::from_u32(0), None);
        assert_eq!(SockOp::from_u32(99), None);
    }

    #[test]
    fn fs_event_layout_and_decoding() {
        assert_eq!(core::mem::align_of::<FsEvent>(), 8);
        assert_eq!(FS_EVENT_SIZE, 280);

        let mut bytes = [0u8; 280];
        bytes[0..4].copy_from_slice(&100u32.to_ne_bytes()); // pid
        bytes[4..8].copy_from_slice(&FsOp::Write.as_u32().to_ne_bytes()); // op
        bytes[8..16].copy_from_slice(&2_000_000_000u64.to_ne_bytes()); // timestamp
        bytes[16..20].copy_from_slice(&8u32.to_ne_bytes()); // path_len
        bytes[20..28].copy_from_slice(b"/etc/foo");

        let event = decode_fs(&bytes).expect("280-byte frame decodes");
        assert_eq!(event.pid, 100);
        assert_eq!(event.op, FsOp::Write.as_u32());
        assert_eq!(event.timestamp_ms, 2_000_000_000);
        assert_eq!(event.path_len, 8);
        assert_eq!(&event.path[..8], b"/etc/foo");

        // Oversized path_len must be rejected
        bytes[16..20].copy_from_slice(&257u32.to_ne_bytes());
        assert_eq!(decode_fs(&bytes), None);
    }

    #[test]
    fn fs_op_tags_round_trip() {
        assert_eq!(FsOp::from_u32(FsOp::Read.as_u32()), Some(FsOp::Read));
        assert_eq!(FsOp::from_u32(FsOp::Write.as_u32()), Some(FsOp::Write));
        assert_eq!(FsOp::from_u32(0), None);
        assert_eq!(FsOp::from_u32(99), None);
    }
}
