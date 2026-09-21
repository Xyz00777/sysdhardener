//! Low-level ptrace register/memory helpers.
//!
//! Extracted from `capture.rs` to keep that module under the 250
//! pure-LOC ceiling. These functions are the unsafe ptrace
//! primitives the capture loop composes: reading the register file,
//! reading a `sockaddr` from the tracee's memory, and the family
//! decoding.

// `pub(super)` items inside a private module trip
// `redundant_pub_crate`; the items are crate-visible by
// construction and the explicit marker is intentional for the
// helper module's contract.
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) markers document the helper module's crate-local intent"
)]

use sysdhardener_core::AddressFamily;
use sysdhardener_core::ObservedEvent;

use crate::decode::decode_syscall_indexed_fs;
use crate::fs_trace::capture_fs_entry;
use crate::syscall::SyscallNumber;
use crate::tracee::PendingSyscall;

use super::ObserveError;

use crate::arch::SyscallRegs;

/// Handle a syscall-entry stop: capture socket and filesystem arguments.
pub(super) fn capture_entry(pid: libc::pid_t, regs: &SyscallRegs) -> Option<PendingSyscall> {
    let number: u64 = regs.syscall_nr();
    let syscall = crate::syscall::syscall_number_from_regs(number)?;
    let family: Option<AddressFamily> = match syscall {
        SyscallNumber::Socket => family_from_domain(regs.arg0()),
        SyscallNumber::Connect | SyscallNumber::Bind => family_from_sockaddr(pid, regs.arg1()),
        SyscallNumber::SendTo => family_from_sockaddr(pid, regs.arg4()),
        _ => None,
    };
    let socket_type: Option<u64> = match syscall {
        SyscallNumber::Socket => Some(regs.arg1()),
        _ => None,
    };
    let sockaddr_addr: Option<u64> = match syscall {
        SyscallNumber::Accept | SyscallNumber::GetSockName | SyscallNumber::GetPeerName => {
            Some(regs.arg1())
        }
        SyscallNumber::RecvFrom => Some(regs.arg4()),
        _ => None,
    };
    let fs_info = capture_fs_entry(pid, regs);
    Some(PendingSyscall {
        syscall,
        family,
        socket_type,
        sockaddr_addr,
        fs_info,
    })
}

/// Handle a syscall-exit stop: read the return value, resolve the
/// sockaddr family (the kernel wrote the address into the buffer the
/// tracee passed at entry), and decode the event stamped with the
/// producing tracee's pid.
pub(super) fn handle_exit(
    pid: libc::pid_t,
    regs: &SyscallRegs,
    pending: Option<PendingSyscall>,
    events: &mut Vec<ObservedEvent>,
) -> Option<PendingSyscall> {
    let retval: i64 = regs.retval();
    if let Some(pending) = pending {
        let family: Option<AddressFamily> = pending.family.or_else(|| {
            if retval < 0 {
                None
            } else {
                pending
                    .sockaddr_addr
                    .and_then(|addr| family_from_sockaddr(pid, addr))
            }
        });
        let now_ms: i64 = now_unix_ms();
        let cgroup: Option<String> = read_tracee_cgroup(pid);
        let index: usize = events.len();
        let fs_ref = pending.fs_info.as_ref().map(|(p, w)| (p.as_str(), *w));
        events.push(decode_syscall_indexed_fs(
            pending.syscall,
            family,
            retval,
            now_ms,
            Some(pid),
            pending.socket_type,
            cgroup,
            index,
            fs_ref,
        ));
    }
    None
}

/// Read the register file of a stopped traced child.
pub(super) fn read_regs(pid: libc::pid_t) -> Result<SyscallRegs, ObserveError> {
    crate::arch::read_regs(pid)
}

/// Resolve the address family from a `socket` domain argument.
/// The Linux ABI family numbers are stable constants; matching them
/// as u64 literals avoids the cast lints.
#[rustfmt::skip]
const fn family_from_domain(domain: u64) -> Option<AddressFamily> {
    match domain {
        1 => Some(AddressFamily::Unix), 2 => Some(AddressFamily::Inet),
        10 => Some(AddressFamily::Inet6), 16 => Some(AddressFamily::Netlink),
        17 => Some(AddressFamily::Packet), _ => None,
    }
}

/// Resolve the address family from a `sockaddr*` argument by reading
/// the first two bytes (the `sa_family_t`) from the target's memory.
///
/// # Safety
/// The caller must hold a stopped traced child at `pid`; the pointer
/// is the child's own address space, read via `PTRACE_PEEKDATA`.
fn family_from_sockaddr(pid: libc::pid_t, addr: u64) -> Option<AddressFamily> {
    if addr == 0 {
        return None;
    }
    // SAFETY: PTRACE_PEEKDATA reads one word from the child's
    // address space at `addr`; the child is stopped, so the memory
    // is stable. Since -1 can be a valid word, we clear errno
    // before the call and check whether errno was set.
    let word: libc::c_long = unsafe {
        *libc::__errno_location() = 0;
        libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            addr as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if word == -1 {
        let errno: i32 = unsafe { *libc::__errno_location() };
        if errno != 0 {
            return None;
        }
    }
    // The first two bytes of a sockaddr are the sa_family_t. The
    // Linux ABI family numbers are stable constants; matching them
    // as u16 literals avoids the cast lints.
    let bytes = word.to_ne_bytes();
    let family: u16 = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        1 => Some(AddressFamily::Unix),
        2 => Some(AddressFamily::Inet),
        10 => Some(AddressFamily::Inet6),
        16 => Some(AddressFamily::Netlink),
        17 => Some(AddressFamily::Packet),
        _ => None,
    }
}

/// Current wall-clock time in Unix-epoch milliseconds.
pub(super) fn now_unix_ms() -> i64 {
    // SAFETY: clock_gettime writes into the timespec; the struct is
    // the exact ABI type.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let ts_ptr: *mut libc::timespec = std::ptr::addr_of_mut!(ts);
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, ts_ptr);
    }
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// Read the cgroup path of a tracee from `/proc/<pid>/cgroup`.
///
/// The file carries one line per hierarchy: `0::/path` on cgroup v2
/// and `1:controller:/path` on cgroup v1. The v2 line is preferred
/// when present; otherwise
/// the second-colon split of the first line is used (works for both
/// formats). Returns `None` when the file is unreadable or the path
/// segment is empty — the observer never fabricates a cgroup.
pub(super) fn read_tracee_cgroup(pid: libc::pid_t) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let text = std::fs::read_to_string(path).ok()?;
    parse_cgroup_text(&text)
}

pub(super) fn parse_cgroup_text(text: &str) -> Option<String> {
    let v2 = text.lines().find(|l| l.starts_with("0::"));
    let v1_systemd = text.lines().find(|l| l.contains(":name=systemd:"));
    let line = v2.or(v1_systemd).or_else(|| text.lines().next())?;
    let path_part = line.split("::").nth(1).or_else(|| {
        // cgroup v1: `hierarchy-ID:controller-list:cgroup-path`
        line.splitn(3, ':').nth(2)
    })?;
    if path_part.is_empty() {
        return None;
    }
    Some(path_part.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_out_parameter_syscall_does_not_decode_family() {
        let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        #[cfg(target_arch = "x86_64")]
        {
            raw.rax = u64::from_ne_bytes((-11i64).to_ne_bytes());
            raw.rsi = 0xdead_beef;
        }
        #[cfg(target_arch = "aarch64")]
        {
            raw.regs[0] = u64::from_ne_bytes((-11i64).to_ne_bytes());
            raw.regs[1] = 0xdead_beef;
        }
        let regs = SyscallRegs::from_raw(raw);
        let mut events = Vec::new();
        let pending = Some(PendingSyscall {
            syscall: SyscallNumber::Accept,
            family: None,
            socket_type: None,
            sockaddr_addr: Some(0xdead_beef),
            fs_info: None,
        });

        let pending_after = handle_exit(1, &regs, pending, &mut events);
        assert!(pending_after.is_none());
        assert_eq!(events.len(), 1);
        let event = events.first().expect("event exists");
        assert_eq!(event.address_family(), AddressFamily::Other("unknown"));
        assert_eq!(event.outcome(), sysdhardener_core::EventOutcome::Error);
    }

    #[test]
    fn cgroup_parser_prioritizes_systemd_hierarchy_on_v1() {
        let v1_text = "12:memory:/\n1:name=systemd:/system.slice/target.service\n";
        assert_eq!(
            parse_cgroup_text(v1_text),
            Some("/system.slice/target.service".to_owned())
        );
        let v2_text = "0::/user.slice/user-1000.slice/app.service\n";
        assert_eq!(
            parse_cgroup_text(v2_text),
            Some("/user.slice/user-1000.slice/app.service".to_owned())
        );
    }

    #[test]
    fn cgroup_parser_preserves_colons_in_cgroup_path() {
        let v1_text = "1:name=systemd:/system.slice/foo:bar.service\n";
        assert_eq!(
            parse_cgroup_text(v1_text),
            Some("/system.slice/foo:bar.service".to_owned())
        );
    }
}
