//! x86-64 Linux ptrace register access and syscall mapping.

#![allow(
    clippy::redundant_pub_crate,
    reason = "nested architecture submodules expose crate-visible items"
)]

use crate::capture::ObserveError;
use crate::fs_trace::{
    dirfd_arg, is_write_flags, read_tracee_string, read_tracee_u64, resolve_path,
};
use crate::syscall::SyscallNumber;

/// Wrapper around `libc::user_regs_struct` on x86-64.
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
        self.raw.orig_rax
    }

    #[must_use]
    pub(crate) const fn retval(&self) -> i64 {
        i64::from_ne_bytes(self.raw.rax.to_ne_bytes())
    }

    #[must_use]
    pub(crate) const fn arg0(&self) -> u64 {
        self.raw.rdi
    }

    #[must_use]
    pub(crate) const fn arg1(&self) -> u64 {
        self.raw.rsi
    }

    #[must_use]
    pub(crate) const fn arg2(&self) -> u64 {
        self.raw.rdx
    }

    #[must_use]
    pub(crate) const fn arg3(&self) -> u64 {
        self.raw.r10
    }

    #[must_use]
    pub(crate) const fn arg4(&self) -> u64 {
        self.raw.r8
    }
}

pub(crate) fn read_regs(pid: libc::pid_t) -> Result<SyscallRegs, ObserveError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let regs_ptr: *mut libc::c_void = std::ptr::addr_of_mut!(regs).cast();
    let rc: libc::c_long = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs_ptr,
        )
    };
    if rc < 0 {
        return Err(ObserveError::Registers("PTRACE_GETREGS failed".to_owned()));
    }
    Ok(SyscallRegs::from_raw(regs))
}

pub(crate) fn capture_fs_args(pid: libc::pid_t, regs: &SyscallRegs) -> Option<(String, bool)> {
    let (dirfd, path_addr) = match regs.syscall_nr() {
        257 => {
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
        2 => {
            let raw = read_tracee_string(pid, regs.arg0(), 4096)?;
            return Some((
                resolve_path(pid, i64::from(libc::AT_FDCWD), &raw),
                is_write_flags(regs.arg1()),
            ));
        }
        85 | 83 | 87 | 84 | 76 | 133 | 90 | 92 | 94 | 132 => {
            (i64::from(libc::AT_FDCWD), regs.arg0())
        }
        82 | 88 | 86 => (i64::from(libc::AT_FDCWD), regs.arg1()),
        258 | 263 | 259 | 268 | 260 | 280 => (dirfd_arg(regs.arg0()), regs.arg1()),
        266 => (dirfd_arg(regs.arg1()), regs.arg2()),
        264 | 316 | 265 => (dirfd_arg(regs.arg2()), regs.arg3()),
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
        41 | 53 => Some(SyscallNumber::Socket),
        42 => Some(SyscallNumber::Connect),
        49 => Some(SyscallNumber::Bind),
        43 | 288 => Some(SyscallNumber::Accept),
        44 => Some(SyscallNumber::SendTo),
        45 => Some(SyscallNumber::RecvFrom),
        51 => Some(SyscallNumber::GetSockName),
        52 => Some(SyscallNumber::GetPeerName),
        2 => Some(SyscallNumber::Capability("open")),
        9 => Some(SyscallNumber::Capability("mmap")),
        16 => Some(SyscallNumber::Capability("ioctl")),
        21 => Some(SyscallNumber::Capability("access")),
        31 => Some(SyscallNumber::Capability("shmctl")),
        54 => Some(SyscallNumber::Capability("setsockopt")),
        62 => Some(SyscallNumber::Capability("kill")),
        66 => Some(SyscallNumber::Capability("semctl")),
        71 => Some(SyscallNumber::Capability("msgctl")),
        72 => Some(SyscallNumber::Capability("fcntl")),
        76 => Some(SyscallNumber::Capability("truncate")),
        82 => Some(SyscallNumber::Capability("rename")),
        83 => Some(SyscallNumber::Capability("mkdir")),
        84 => Some(SyscallNumber::Capability("rmdir")),
        85 => Some(SyscallNumber::Capability("creat")),
        86 => Some(SyscallNumber::Capability("link")),
        87 => Some(SyscallNumber::Capability("unlink")),
        88 => Some(SyscallNumber::Capability("symlink")),
        89 => Some(SyscallNumber::Capability("readlink")),
        90 => Some(SyscallNumber::Capability("chmod")),
        91 => Some(SyscallNumber::Capability("fchmod")),
        92 => Some(SyscallNumber::Capability("chown")),
        93 => Some(SyscallNumber::Capability("fchown")),
        94 => Some(SyscallNumber::Capability("lchown")),
        101 => Some(SyscallNumber::Capability("ptrace")),
        103 => Some(SyscallNumber::Capability("syslog")),
        105 => Some(SyscallNumber::Capability("setuid")),
        106 => Some(SyscallNumber::Capability("setgid")),
        113 => Some(SyscallNumber::Capability("setreuid")),
        114 => Some(SyscallNumber::Capability("setregid")),
        116 => Some(SyscallNumber::Capability("setgroups")),
        117 => Some(SyscallNumber::Capability("setresuid")),
        119 => Some(SyscallNumber::Capability("setresgid")),
        122 => Some(SyscallNumber::Capability("setfsuid")),
        123 => Some(SyscallNumber::Capability("setfsgid")),
        126 => Some(SyscallNumber::Capability("capset")),
        133 => Some(SyscallNumber::Capability("mknod")),
        140 => Some(SyscallNumber::Capability("nice")),
        141 => Some(SyscallNumber::Capability("setpriority")),
        142 => Some(SyscallNumber::Capability("sched_setparam")),
        144 => Some(SyscallNumber::Capability("sched_setscheduler")),
        149 => Some(SyscallNumber::Capability("mlock")),
        151 => Some(SyscallNumber::Capability("mlockall")),
        153 => Some(SyscallNumber::Capability("vhangup")),
        155 => Some(SyscallNumber::Capability("pivot_root")),
        157 => Some(SyscallNumber::Capability("prctl")),
        159 => Some(SyscallNumber::Capability("adjtimex")),
        160 => Some(SyscallNumber::Capability("setrlimit")),
        161 => Some(SyscallNumber::Capability("chroot")),
        163 => Some(SyscallNumber::Capability("acct")),
        164 => Some(SyscallNumber::Capability("settimeofday")),
        165 => Some(SyscallNumber::Capability("mount")),
        166 => Some(SyscallNumber::Capability("umount2")),
        167 => Some(SyscallNumber::Capability("swapon")),
        168 => Some(SyscallNumber::Capability("swapoff")),
        169 => Some(SyscallNumber::Capability("reboot")),
        170 => Some(SyscallNumber::Capability("sethostname")),
        171 => Some(SyscallNumber::Capability("setdomainname")),
        172 => Some(SyscallNumber::Capability("iopl")),
        173 => Some(SyscallNumber::Capability("ioperm")),
        175 => Some(SyscallNumber::Capability("init_module")),
        176 => Some(SyscallNumber::Capability("delete_module")),
        179 => Some(SyscallNumber::Capability("quotactl")),
        188 => Some(SyscallNumber::Capability("setxattr")),
        189 => Some(SyscallNumber::Capability("lsetxattr")),
        190 => Some(SyscallNumber::Capability("fsetxattr")),
        197 => Some(SyscallNumber::Capability("removexattr")),
        198 => Some(SyscallNumber::Capability("lremovexattr")),
        199 => Some(SyscallNumber::Capability("fremovexattr")),
        200 => Some(SyscallNumber::Capability("tkill")),
        203 => Some(SyscallNumber::Capability("sched_setaffinity")),
        212 => Some(SyscallNumber::Capability("lookup_dcookie")),
        227 => Some(SyscallNumber::Capability("clock_settime")),
        233 => Some(SyscallNumber::Capability("epoll_ctl")),
        234 => Some(SyscallNumber::Capability("tgkill")),
        246 => Some(SyscallNumber::Capability("kexec_load")),
        251 => Some(SyscallNumber::Capability("ioprio_set")),
        257 => Some(SyscallNumber::Capability("openat")),
        258 => Some(SyscallNumber::Capability("mkdirat")),
        259 => Some(SyscallNumber::Capability("mknodat")),
        260 => Some(SyscallNumber::Capability("fchownat")),
        263 => Some(SyscallNumber::Capability("unlinkat")),
        264 => Some(SyscallNumber::Capability("renameat")),
        265 => Some(SyscallNumber::Capability("linkat")),
        266 => Some(SyscallNumber::Capability("symlinkat")),
        267 => Some(SyscallNumber::Capability("readlinkat")),
        268 => Some(SyscallNumber::Capability("fchmodat")),
        269 => Some(SyscallNumber::Capability("faccessat")),
        272 => Some(SyscallNumber::Capability("unshare")),
        280 => Some(SyscallNumber::Capability("utimensat")),
        283 => Some(SyscallNumber::Capability("timerfd_create")),
        298 => Some(SyscallNumber::Capability("perf_event_open")),
        300 => Some(SyscallNumber::Capability("fanotify_init")),
        301 => Some(SyscallNumber::Capability("fanotify_mark")),
        302 => Some(SyscallNumber::Capability("prlimit64")),
        304 => Some(SyscallNumber::Capability("open_by_handle_at")),
        305 => Some(SyscallNumber::Capability("clock_adjtime")),
        308 => Some(SyscallNumber::Capability("setns")),
        310 => Some(SyscallNumber::Capability("process_vm_readv")),
        311 => Some(SyscallNumber::Capability("process_vm_writev")),
        312 => Some(SyscallNumber::Capability("kcmp")),
        313 => Some(SyscallNumber::Capability("finit_module")),
        314 => Some(SyscallNumber::Capability("sched_setattr")),
        316 => Some(SyscallNumber::Capability("renameat2")),
        317 => Some(SyscallNumber::Capability("seccomp")),
        320 => Some(SyscallNumber::Capability("kexec_file_load")),
        321 => Some(SyscallNumber::Capability("bpf")),
        323 => Some(SyscallNumber::Capability("userfaultfd")),
        325 => Some(SyscallNumber::Capability("mlock2")),
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
