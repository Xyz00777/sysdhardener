//! Syscall number mapping for the x86-64 Linux ABI.
//!
//! The observer reads the syscall number from the target's register
//! file at each syscall-entry stop. This module maps the raw number
//! to the typed [`SyscallNumber`] the decoder understands. The
//! numbers are the x86-64 ABI constants (the reference environment
//! is x86-64 Linux); a future aarch64 build needs a second table.
//!
//! The table covers two families:
//! - the socket-family syscalls that carry address-family evidence
//!   (the `RestrictAddressFamilies=` recommendation);
//! - the capability-relevant syscalls from
//!   `docs/research.md`, so the
//!   observer can record which capability-gated operations a service
//!   attempts (and whether the kernel granted them).

/// A syscall the observer recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallNumber {
    /// `socket(domain, type, protocol)` — creates a socket.
    Socket,
    /// `connect(fd, sockaddr, len)` — connects a socket.
    Connect,
    /// `bind(fd, sockaddr, len)` — binds a socket to an address.
    Bind,
    /// `accept(fd, sockaddr, len)` — accepts a connection.
    Accept,
    /// `sendto(fd, buf, len, flags, sockaddr, addrlen)` — sends to a
    /// socket address.
    SendTo,
    /// `recvfrom(fd, buf, len, flags, sockaddr, addrlen)` — receives
    /// from a socket address.
    RecvFrom,
    /// `getsockname(fd, sockaddr, len)` — reads the bound address.
    GetSockName,
    /// `getpeername(fd, sockaddr, len)` — reads the peer address.
    GetPeerName,
    /// A capability-relevant syscall (see the capability map). The
    /// name is the syscall's canonical spelling; the event carries
    /// no address family (these syscalls are not
    /// `RestrictAddressFamilies=` evidence).
    Capability(&'static str),
}

/// Map a target architecture syscall number to the typed [`SyscallNumber`].
/// Returns `None` for syscalls the observer does not decode.
#[must_use]
pub const fn syscall_number_from_regs(number: u64) -> Option<SyscallNumber> {
    crate::arch::syscall_number_from_regs(number)
}

/// Syscalls whose ptrace stops are NOT delivered on the reference
/// kernel (xanmod 7.1.8), though the syscalls execute and return.
///
/// Verified empirically; backlog E-04. Absence is an observation
/// gap, not evidence of non-use.
pub const KNOWN_UNDELIVERED_SYSCALLS: &[&str] = &["getpeername", "setpriority"];

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn maps_mknodat_and_fchmodat() {
        for (num, name) in [
            (259, "mknodat"),
            (268, "fchmodat"),
            (170, "sethostname"),
            (189, "lsetxattr"),
            (190, "fsetxattr"),
            (267, "readlinkat"),
            (269, "faccessat"),
            (437, "openat2"),
            (439, "faccessat2"),
            (317, "seccomp"),
            (426, "io_uring_enter"),
        ] {
            assert_eq!(
                syscall_number_from_regs(num),
                Some(SyscallNumber::Capability(name))
            );
        }
        assert_eq!(syscall_number_from_regs(1), None);
        assert_eq!(syscall_number_from_regs(4), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn maps_x86_64_abi_socket_and_priority_syscalls() {
        assert_eq!(
            syscall_number_from_regs(51),
            Some(SyscallNumber::GetSockName)
        );
        assert_eq!(
            syscall_number_from_regs(52),
            Some(SyscallNumber::GetPeerName)
        );
        assert_eq!(syscall_number_from_regs(53), Some(SyscallNumber::Socket));
        assert_eq!(syscall_number_from_regs(34), None);
        for (num, name) in [
            (141, "setpriority"),
            (159, "adjtimex"),
            (171, "setdomainname"),
            (155, "pivot_root"),
            (168, "swapoff"),
            (305, "clock_adjtime"),
            (320, "kexec_file_load"),
            (142, "sched_setparam"),
            (314, "sched_setattr"),
            (114, "setregid"),
            (140, "nice"),
            (443, "quotactl_fd"),
            (428, "open_tree"),
            (122, "setfsuid"),
            (123, "setfsgid"),
            (153, "vhangup"),
            (251, "ioprio_set"),
            (302, "prlimit64"),
            (304, "open_by_handle_at"),
            (325, "mlock2"),
            (424, "pidfd_send_signal"),
            (438, "pidfd_getfd"),
            (197, "removexattr"),
            (198, "lremovexattr"),
            (199, "fremovexattr"),
            (427, "io_uring_register"),
        ] {
            assert_eq!(
                syscall_number_from_regs(num),
                Some(SyscallNumber::Capability(name))
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn maps_aarch64_abi_syscalls() {
        assert_eq!(syscall_number_from_regs(198), Some(SyscallNumber::Socket));
        assert_eq!(syscall_number_from_regs(200), Some(SyscallNumber::Bind));
        assert_eq!(syscall_number_from_regs(203), Some(SyscallNumber::Connect));
        assert_eq!(
            syscall_number_from_regs(204),
            Some(SyscallNumber::GetSockName)
        );
        assert_eq!(
            syscall_number_from_regs(205),
            Some(SyscallNumber::GetPeerName)
        );
        assert_eq!(
            syscall_number_from_regs(56),
            Some(SyscallNumber::Capability("openat"))
        );
        assert_eq!(
            syscall_number_from_regs(34),
            Some(SyscallNumber::Capability("mkdirat"))
        );
        assert_eq!(
            syscall_number_from_regs(35),
            Some(SyscallNumber::Capability("unlinkat"))
        );
    }
}
