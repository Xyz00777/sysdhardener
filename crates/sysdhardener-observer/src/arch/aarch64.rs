//! AArch64 Linux ptrace register access and syscall mapping.

#![allow(
    clippy::redundant_pub_crate,
    reason = "nested architecture submodules expose crate-visible items"
)]

use crate::capture::ObserveError;
use crate::fs_trace::{
    dirfd_arg, is_write_flags, read_tracee_string, read_tracee_u64, resolve_path,
};
use crate::syscall::SyscallNumber;

/// Wrapper around `libc::user_regs_struct` on aarch64.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SyscallRegs {
    raw: libc::user_regs_struct,
}

impl SyscallRegs {
    #[must_use]
    pub(crate) const fn from_raw(raw: libc::user_regs_struct) -> Self {
        Self { raw }
    }

    #[must_use]
    pub(crate) const fn syscall_nr(&self) -> u64 {
        self.raw.regs[8]
    }

    #[must_use]
    pub(crate) const fn retval(&self) -> i64 {
        i64::from_ne_bytes(self.raw.regs[0].to_ne_bytes())
    }

    #[must_use]
    pub(crate) const fn arg0(&self) -> u64 {
        self.raw.regs[0]
    }

    #[must_use]
    pub(crate) const fn arg1(&self) -> u64 {
        self.raw.regs[1]
    }

    #[must_use]
    pub(crate) const fn arg2(&self) -> u64 {
        self.raw.regs[2]
    }

    #[must_use]
    pub(crate) const fn arg3(&self) -> u64 {
        self.raw.regs[3]
    }

    #[must_use]
    pub(crate) const fn arg4(&self) -> u64 {
        self.raw.regs[4]
    }
}

pub(crate) fn read_regs(pid: libc::pid_t) -> Result<SyscallRegs, ObserveError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(regs).cast(),
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let rc: libc::c_long = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            libc::NT_PRSTATUS as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    if rc < 0 {
        return Err(ObserveError::Registers(
            "PTRACE_GETREGSET failed".to_owned(),
        ));
    }
    Ok(SyscallRegs::from_raw(regs))
}

pub(crate) fn capture_fs_args(pid: libc::pid_t, regs: &SyscallRegs) -> Option<(String, bool)> {
    let (dirfd, path_addr) = match regs.syscall_nr() {
        56 => {
            let raw = read_tracee_string(pid, regs.arg1(), 4096)?;
            return Some((
                resolve_path(pid, dirfd_arg(regs.arg0()), &raw),
                is_write_flags(regs.arg2()),
            ));
        }
        437 => {
            let raw = read_tracee_string(pid, regs.arg1(), 4096)?;
            let flags = read_tracee_u64(pid, regs.arg2()).unwrap_or(0);
            return Some((
                resolve_path(pid, dirfd_arg(regs.arg0()), &raw),
                is_write_flags(flags),
            ));
        }
        45 => (i64::from(libc::AT_FDCWD), regs.arg0()),
        34 | 35 | 33 | 53 | 54 | 88 => (dirfd_arg(regs.arg0()), regs.arg1()),
        36 => (dirfd_arg(regs.arg1()), regs.arg2()),
        38 | 276 | 37 => (dirfd_arg(regs.arg2()), regs.arg3()),
        _ => return None,
    };
    let raw = read_tracee_string(pid, path_addr, 4096)?;
    Some((resolve_path(pid, dirfd, &raw), true))
}

#[allow(
    clippy::too_many_lines,
    reason = "exhaustive architecture syscall table"
)]
pub(crate) const fn syscall_number_from_regs(number: u64) -> Option<SyscallNumber> {
    match number {
        198 => Some(SyscallNumber::Socket),
        200 => Some(SyscallNumber::Bind),
        203 => Some(SyscallNumber::Connect),
        202 | 242 => Some(SyscallNumber::Accept),
        206 => Some(SyscallNumber::SendTo),
        207 => Some(SyscallNumber::RecvFrom),
        204 => Some(SyscallNumber::GetSockName),
        205 => Some(SyscallNumber::GetPeerName),
        5 => Some(SyscallNumber::Capability("setxattr")),
        6 => Some(SyscallNumber::Capability("lsetxattr")),
        7 => Some(SyscallNumber::Capability("fsetxattr")),
        14 => Some(SyscallNumber::Capability("removexattr")),
        15 => Some(SyscallNumber::Capability("lremovexattr")),
        16 => Some(SyscallNumber::Capability("fremovexattr")),
        18 => Some(SyscallNumber::Capability("lookup_dcookie")),
        21 => Some(SyscallNumber::Capability("epoll_ctl")),
        25 => Some(SyscallNumber::Capability("fcntl")),
        29 => Some(SyscallNumber::Capability("ioctl")),
        30 => Some(SyscallNumber::Capability("ioprio_set")),
        33 => Some(SyscallNumber::Capability("mknodat")),
        34 => Some(SyscallNumber::Capability("mkdirat")),
        35 => Some(SyscallNumber::Capability("unlinkat")),
        36 => Some(SyscallNumber::Capability("symlinkat")),
        37 => Some(SyscallNumber::Capability("linkat")),
        38 => Some(SyscallNumber::Capability("renameat")),
        39 => Some(SyscallNumber::Capability("umount2")),
        40 => Some(SyscallNumber::Capability("mount")),
        41 => Some(SyscallNumber::Capability("pivot_root")),
        45 => Some(SyscallNumber::Capability("truncate")),
        48 => Some(SyscallNumber::Capability("faccessat")),
        51 => Some(SyscallNumber::Capability("chroot")),
        52 => Some(SyscallNumber::Capability("fchmod")),
        53 => Some(SyscallNumber::Capability("fchmodat")),
        54 => Some(SyscallNumber::Capability("fchownat")),
        55 => Some(SyscallNumber::Capability("fchown")),
        56 => Some(SyscallNumber::Capability("openat")),
        58 => Some(SyscallNumber::Capability("vhangup")),
        60 => Some(SyscallNumber::Capability("quotactl")),
        78 => Some(SyscallNumber::Capability("readlinkat")),
        85 => Some(SyscallNumber::Capability("timerfd_create")),
        88 => Some(SyscallNumber::Capability("utimensat")),
        89 => Some(SyscallNumber::Capability("acct")),
        91 => Some(SyscallNumber::Capability("capset")),
        97 => Some(SyscallNumber::Capability("unshare")),
        104 => Some(SyscallNumber::Capability("kexec_load")),
        105 => Some(SyscallNumber::Capability("init_module")),
        106 => Some(SyscallNumber::Capability("delete_module")),
        112 => Some(SyscallNumber::Capability("clock_settime")),
        116 => Some(SyscallNumber::Capability("syslog")),
        117 => Some(SyscallNumber::Capability("ptrace")),
        119 => Some(SyscallNumber::Capability("sched_setscheduler")),
        121 => Some(SyscallNumber::Capability("sched_setparam")),
        122 => Some(SyscallNumber::Capability("sched_setaffinity")),
        129 => Some(SyscallNumber::Capability("kill")),
        130 => Some(SyscallNumber::Capability("tkill")),
        131 => Some(SyscallNumber::Capability("tgkill")),
        140 => Some(SyscallNumber::Capability("setpriority")),
        142 => Some(SyscallNumber::Capability("reboot")),
        143 => Some(SyscallNumber::Capability("setregid")),
        144 => Some(SyscallNumber::Capability("setgid")),
        145 => Some(SyscallNumber::Capability("setreuid")),
        146 => Some(SyscallNumber::Capability("setuid")),
        147 => Some(SyscallNumber::Capability("setresuid")),
        149 => Some(SyscallNumber::Capability("setresgid")),
        151 => Some(SyscallNumber::Capability("setfsuid")),
        152 => Some(SyscallNumber::Capability("setfsgid")),
        158 => Some(SyscallNumber::Capability("setgroups")),
        161 => Some(SyscallNumber::Capability("sethostname")),
        162 => Some(SyscallNumber::Capability("setdomainname")),
        164 => Some(SyscallNumber::Capability("setrlimit")),
        167 => Some(SyscallNumber::Capability("prctl")),
        170 => Some(SyscallNumber::Capability("settimeofday")),
        171 => Some(SyscallNumber::Capability("adjtimex")),
        187 => Some(SyscallNumber::Capability("msgctl")),
        191 => Some(SyscallNumber::Capability("semctl")),
        195 => Some(SyscallNumber::Capability("shmctl")),
        208 => Some(SyscallNumber::Capability("setsockopt")),
        222 => Some(SyscallNumber::Capability("mmap")),
        224 => Some(SyscallNumber::Capability("swapon")),
        225 => Some(SyscallNumber::Capability("swapoff")),
        228 => Some(SyscallNumber::Capability("mlock")),
        230 => Some(SyscallNumber::Capability("mlockall")),
        241 => Some(SyscallNumber::Capability("perf_event_open")),
        261 => Some(SyscallNumber::Capability("prlimit64")),
        262 => Some(SyscallNumber::Capability("fanotify_init")),
        263 => Some(SyscallNumber::Capability("fanotify_mark")),
        265 => Some(SyscallNumber::Capability("open_by_handle_at")),
        266 => Some(SyscallNumber::Capability("clock_adjtime")),
        268 => Some(SyscallNumber::Capability("setns")),
        270 => Some(SyscallNumber::Capability("process_vm_readv")),
        271 => Some(SyscallNumber::Capability("process_vm_writev")),
        272 => Some(SyscallNumber::Capability("kcmp")),
        273 => Some(SyscallNumber::Capability("finit_module")),
        274 => Some(SyscallNumber::Capability("sched_setattr")),
        276 => Some(SyscallNumber::Capability("renameat2")),
        277 => Some(SyscallNumber::Capability("seccomp")),
        280 => Some(SyscallNumber::Capability("bpf")),
        282 => Some(SyscallNumber::Capability("userfaultfd")),
        284 => Some(SyscallNumber::Capability("mlock2")),
        294 => Some(SyscallNumber::Capability("kexec_file_load")),
        424 => Some(SyscallNumber::Capability("pidfd_send_signal")),
        425 => Some(SyscallNumber::Capability("io_uring_setup")),
        426 => Some(SyscallNumber::Capability("io_uring_enter")),
        427 => Some(SyscallNumber::Capability("io_uring_register")),
        428 => Some(SyscallNumber::Capability("open_tree")),
        429 => Some(SyscallNumber::Capability("move_mount")),
        430 => Some(SyscallNumber::Capability("fsopen")),
        431 => Some(SyscallNumber::Capability("fsconfig")),
        432 => Some(SyscallNumber::Capability("fsmount")),
        433 => Some(SyscallNumber::Capability("fspick")),
        434 => Some(SyscallNumber::Capability("pidfd_open")),
        435 => Some(SyscallNumber::Capability("clone3")),
        437 => Some(SyscallNumber::Capability("openat2")),
        438 => Some(SyscallNumber::Capability("pidfd_getfd")),
        439 => Some(SyscallNumber::Capability("faccessat2")),
        442 => Some(SyscallNumber::Capability("mount_setattr")),
        443 => Some(SyscallNumber::Capability("quotactl_fd")),
        _ => None,
    }
}
