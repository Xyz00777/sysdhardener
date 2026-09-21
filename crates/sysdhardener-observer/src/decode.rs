//! Decode captured syscall arguments into typed observed events.
//!
//! Pure module: takes the raw register values captured at a syscall
//! entry/exit pair and produces the typed [`ObservedEvent`] the
//! analysis engine consumes. No I/O, no ptrace, no unsafe.

use sysdhardener_core::ObservedEvent;
use sysdhardener_core::{AddressFamily, EventOutcome, FixtureTimestamp, SourceId};

use crate::syscall::SyscallNumber;

/// The source ID the observer stamps on every captured event. The
/// registry row is SRC-12 (live observer).
pub const OBSERVER_SOURCE_ID: SourceId = SourceId::from_static("SRC-12");

/// One decoded syscall: the typed syscall, its address-family
/// argument, and the outcome (success/failure) from the return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSyscall {
    /// The typed syscall.
    pub syscall: SyscallNumber,
    /// The address family the syscall targeted, when the argument
    /// carried one.
    pub family: Option<AddressFamily>,
    /// Whether the syscall returned success (0) or an error.
    pub success: bool,
    /// The raw return value (errno magnitude on failure).
    pub retval: i64,
    /// A short human-readable argument summary (e.g. the socket
    /// type, or the sockaddr family tag).
    pub args: String,
}

/// Decode a captured syscall into a typed [`ObservedEvent`].
///
/// `syscall` is the typed syscall, `family_arg` is the raw first
/// argument (the `domain` for `socket`, or the `sockaddr` pointer
/// for the others — the caller resolves the family from the sockaddr
/// before calling), `retval` is the syscall's return value,
/// `timestamp_unix_ms` is the capture time, and `pid` is the tracee
/// that performed the syscall.
///
/// The event carries the observer's source ID (SRC-12), a stable
/// event ID derived from the syscall name and the timestamp, and the
/// typed family/outcome labels the engine requires.
/// Decode a captured syscall stop into an [`ObservedEvent`] disambiguated
/// by event index within the capture batch.
#[allow(
    clippy::too_many_arguments,
    reason = "the event shape is fixed by the wire contract"
)]
#[must_use]
pub fn decode_syscall_indexed(
    syscall: SyscallNumber,
    family: Option<AddressFamily>,
    retval: i64,
    timestamp_unix_ms: i64,
    pid: Option<i32>,
    socket_type: Option<u64>,
    cgroup: Option<String>,
    index: usize,
) -> ObservedEvent {
    decode_syscall_indexed_fs(
        syscall,
        family,
        retval,
        timestamp_unix_ms,
        pid,
        socket_type,
        cgroup,
        index,
        None,
    )
}

/// Decode a captured syscall stop into an [`ObservedEvent`] with optional filesystem info.
#[allow(
    clippy::too_many_arguments,
    reason = "the event shape is fixed by the wire contract"
)]
#[must_use]
pub fn decode_syscall_indexed_fs(
    syscall: SyscallNumber,
    family: Option<AddressFamily>,
    retval: i64,
    timestamp_unix_ms: i64,
    pid: Option<i32>,
    socket_type: Option<u64>,
    cgroup: Option<String>,
    index: usize,
    fs_info: Option<(&str, bool)>,
) -> ObservedEvent {
    let outcome: EventOutcome = if retval >= 0 {
        EventOutcome::Success
    } else if retval == -i64::from(libc::EINTR)
        || retval == -512  // ERESTARTSYS
        || retval == -513  // ERESTARTNOINTR
        || retval == -514  // ERESTARTNOHAND
        || retval == -516
    // ERESTART_RESTARTBLOCK
    {
        EventOutcome::Interrupted
    } else {
        EventOutcome::Error
    };
    let event_family: AddressFamily = match syscall {
        SyscallNumber::Capability(_) => AddressFamily::Other("capability"),
        _ => family.unwrap_or(AddressFamily::Other("unknown")),
    };
    let family_label: &str = match event_family {
        AddressFamily::Unix => "unix",
        AddressFamily::Inet => "inet",
        AddressFamily::Inet6 => "inet6",
        AddressFamily::Netlink => "netlink",
        AddressFamily::Packet => "packet",
        AddressFamily::Other(tag) => tag,
        _ => "other",
    };
    let syscall_name: &str = match syscall {
        SyscallNumber::Socket => "socket",
        SyscallNumber::Connect => "connect",
        SyscallNumber::Bind => "bind",
        SyscallNumber::Accept => "accept",
        SyscallNumber::SendTo => "sendto",
        SyscallNumber::RecvFrom => "recvfrom",
        SyscallNumber::GetSockName => "getsockname",
        SyscallNumber::GetPeerName => "getpeername",
        SyscallNumber::Capability(name) => name,
    };
    let mut args: String = format!("{syscall_name} family={family_label} ret={retval}");
    if let Some(sock_type) = socket_type {
        let base_type: u64 = sock_type & 0xf;
        let type_label: &str = match base_type {
            1 => "stream",
            2 => "dgram",
            3 => "raw",
            5 => "seqpacket",
            _ => "other",
        };
        args = format!("{args} type={type_label}");
    }
    if let Some((path, is_write)) = fs_info {
        args = format!("{args} path={path} write={is_write}");
    }
    let event_id: String = format!("obs-{syscall_name}-{timestamp_unix_ms}-{index}");
    ObservedEvent::new_with_pid_cgroup(
        OBSERVER_SOURCE_ID,
        event_id,
        FixtureTimestamp::from_raw_checked(timestamp_unix_ms),
        event_family,
        outcome,
        args,
        pid,
        cgroup,
    )
}

/// Decode a captured syscall stop into an [`ObservedEvent`].
#[allow(
    clippy::too_many_arguments,
    reason = "the event shape is fixed by the wire contract"
)]
#[must_use]
pub fn decode_syscall(
    syscall: SyscallNumber,
    family: Option<AddressFamily>,
    retval: i64,
    timestamp_unix_ms: i64,
    pid: Option<i32>,
    socket_type: Option<u64>,
    cgroup: Option<String>,
) -> ObservedEvent {
    decode_syscall_indexed(
        syscall,
        family,
        retval,
        timestamp_unix_ms,
        pid,
        socket_type,
        cgroup,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_type_masks_cloexec_and_nonblock() {
        let event_raw_cloexec = decode_syscall(
            SyscallNumber::Socket,
            Some(AddressFamily::Inet),
            3,
            100,
            Some(1),
            Some(3 | 0x80000), // SOCK_RAW | SOCK_CLOEXEC
            None,
        );
        assert!(
            event_raw_cloexec.args().contains("type=raw"),
            "expected type=raw, got: {}",
            event_raw_cloexec.args()
        );

        let event_stream_nonblock = decode_syscall(
            SyscallNumber::Socket,
            Some(AddressFamily::Inet),
            3,
            100,
            Some(1),
            Some(1 | 0x800), // SOCK_STREAM | SOCK_NONBLOCK
            None,
        );
        assert!(
            event_stream_nonblock.args().contains("type=stream"),
            "expected type=stream, got: {}",
            event_stream_nonblock.args()
        );
    }

    #[test]
    fn decode_syscall_indexed_disambiguates_same_timestamp() {
        let e1 = decode_syscall_indexed(
            SyscallNumber::Connect,
            Some(AddressFamily::Inet),
            0,
            100,
            Some(1),
            None,
            None,
            0,
        );
        let e2 = decode_syscall_indexed(
            SyscallNumber::Connect,
            Some(AddressFamily::Inet),
            0,
            100,
            Some(1),
            None,
            None,
            1,
        );
        assert_ne!(e1.event_id(), e2.event_id());
        assert_eq!(e1.event_id(), "obs-connect-100-0");
        assert_eq!(e2.event_id(), "obs-connect-100-1");
    }

    #[test]
    fn eintr_decodes_as_interrupted() {
        let retval = -i64::from(libc::EINTR);
        let ev = decode_syscall_indexed(
            SyscallNumber::Connect,
            Some(AddressFamily::Inet),
            retval,
            200,
            Some(1),
            None,
            None,
            0,
        );
        assert_eq!(ev.outcome(), EventOutcome::Interrupted);
    }

    #[test]
    fn kernel_restart_errnos_decode_as_interrupted() {
        // ERESTARTSYS(512), ERESTARTNOINTR(513),
        // ERESTARTNOHAND(514), ERESTART_RESTARTBLOCK(516)
        for errno in [512_i64, 513, 514, 516] {
            let ev = decode_syscall_indexed(
                SyscallNumber::Socket,
                Some(AddressFamily::Unix),
                -errno,
                300,
                Some(1),
                None,
                None,
                0,
            );
            assert_eq!(
                ev.outcome(),
                EventOutcome::Interrupted,
                "retval -{errno} must decode as Interrupted"
            );
        }
    }
}
