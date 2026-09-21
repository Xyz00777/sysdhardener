//! Capability evidence aggregation and recommendation.
//!
//! The observer records capability-relevant syscalls as
//! `Other("capability")` events whose `args` carry the syscall name
//! (e.g. mount family=capability ret=-1). This module maps those
//! syscall names to the capabilities they gate (the table from
//! `docs/research.md`, SRC-13), and
//! derives a provisional `CapabilityBoundingSet=~CAP_X` candidate:
//! capabilities with **no successful use** of any gated syscall are
//! candidates for removal.
//!
//! The candidate is provisional, exactly like the address-family
//! candidate: absence of observed use is not proof of non-need.

use crate::observed_event::ObservedEvent;
use crate::source_id::SourceId;

/// A Linux capability (the closed set of 41, SRC-13).
///
/// Serializes to the canonical `CAP_<NAME>` spelling, matching the
/// detailed/concise renderers and the capability map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LinuxCapability {
    /// `CAP_CHOWN` — `chown`/`fchown`/`lchown`/`fchownat`.
    Chown,
    /// `CAP_DAC_OVERRIDE` — bypass file permission checks.
    DacOverride,
    /// `CAP_DAC_READ_SEARCH` — bypass read-only permission checks.
    DacReadSearch,
    /// `CAP_FOWNER` — bypass ownership checks.
    Fowner,
    /// `CAP_FSETID` — set `setuid`/`setgid` bits.
    Fsetid,
    /// `CAP_KILL` — `kill` any process.
    Kill,
    /// `CAP_SETGID` — `setgid`/`setgroups`.
    Setgid,
    /// `CAP_SETUID` — `setuid`/`setreuid`/`setresuid`.
    Setuid,
    /// `CAP_SETPCAP` — `capset`/`prctl` capability manipulation.
    Setpcap,
    /// `CAP_LINUX_IMMUTABLE` — `ioctl` immutable/append flags.
    LinuxImmutable,
    /// `CAP_NET_BIND_SERVICE` — `bind` to privileged ports.
    NetBindService,
    /// `CAP_NET_BROADCAST` — raw `socket` broadcast.
    NetBroadcast,
    /// `CAP_NET_ADMIN` — netlink/interface configuration.
    NetAdmin,
    /// `CAP_NET_RAW` — raw/packet `socket`s.
    NetRaw,
    /// `CAP_IPC_LOCK` — `mlock`/`mmap` `MAP_LOCKED`.
    IpcLock,
    /// `CAP_IPC_OWNER` — bypass IPC ownership.
    IpcOwner,
    /// `CAP_SYS_MODULE` — module load/unload.
    SysModule,
    /// `CAP_SYS_RAWIO` — `iopl`/`ioperm`/dev mem.
    SysRawio,
    /// `CAP_SYS_CHROOT` — `chroot`.
    SysChroot,
    /// `CAP_SYS_PTRACE` — `ptrace`/`process_vm_readv`/`process_vm_writev`.
    SysPtrace,
    /// `CAP_SYS_PACCT` — `acct`.
    SysPacct,
    /// `CAP_SYS_ADMIN` — `mount`/`setns`/`unshare`/`bpf`/`perf_event_open`.
    SysAdmin,
    /// `CAP_SYS_BOOT` — `reboot`/`kexec_load`.
    SysBoot,
    /// `CAP_SYS_NICE` — `setpriority`/`sched_setscheduler`/`sched_setaffinity`.
    SysNice,
    /// `CAP_SYS_RESOURCE` — `setrlimit`/`mknod`.
    SysResource,
    /// `CAP_SYS_TIME` — `settimeofday`/`clock_settime`.
    SysTime,
    /// `CAP_SYS_TTY_CONFIG` — TIOCSTI.
    SysTtyConfig,
    /// `CAP_MKNOD` — `mknod` device nodes.
    Mknod,
    /// `CAP_LEASE` — `fcntl` (`F_SETLEASE`).
    Lease,
    /// `CAP_AUDIT_WRITE` — write to audit log.
    AuditWrite,
    /// `CAP_AUDIT_CONTROL` — audit control.
    AuditControl,
    /// `CAP_SETFCAP` — `setxattr` security.capability.
    Setfcap,
    /// `CAP_MAC_OVERRIDE` — MAC override.
    MacOverride,
    /// `CAP_MAC_ADMIN` — MAC admin.
    MacAdmin,
    /// `CAP_SYSLOG` — `syslog`/`klogctl`/dmesg.
    Syslog,
    /// `CAP_WAKE_ALARM` — timerfd alarms.
    WakeAlarm,
    /// `CAP_BLOCK_SUSPEND` — epoll EPOLLWAKEUP.
    BlockSuspend,
    /// `CAP_AUDIT_READ` — audit netlink read.
    AuditRead,
    /// `CAP_PERFMON` — `perf_event_open`.
    Perfmon,
    /// `CAP_BPF` — `bpf` programs.
    Bpf,
    /// `CAP_CHECKPOINT_RESTORE` — `clone3`/pidfd/`kcmp`.
    CheckpointRestore,
}

impl LinuxCapability {
    /// The systemd spelling (`CAP_X`) used in
    /// `CapabilityBoundingSet=~CAP_X`.
    #[must_use]
    #[rustfmt::skip]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chown => "CAP_CHOWN", Self::DacOverride => "CAP_DAC_OVERRIDE",
            Self::DacReadSearch => "CAP_DAC_READ_SEARCH", Self::Fowner => "CAP_FOWNER",
            Self::Fsetid => "CAP_FSETID", Self::Kill => "CAP_KILL",
            Self::Setgid => "CAP_SETGID", Self::Setuid => "CAP_SETUID",
            Self::Setpcap => "CAP_SETPCAP", Self::LinuxImmutable => "CAP_LINUX_IMMUTABLE",
            Self::NetBindService => "CAP_NET_BIND_SERVICE", Self::NetBroadcast => "CAP_NET_BROADCAST",
            Self::NetAdmin => "CAP_NET_ADMIN", Self::NetRaw => "CAP_NET_RAW",
            Self::IpcLock => "CAP_IPC_LOCK", Self::IpcOwner => "CAP_IPC_OWNER",
            Self::SysModule => "CAP_SYS_MODULE", Self::SysRawio => "CAP_SYS_RAWIO",
            Self::SysChroot => "CAP_SYS_CHROOT", Self::SysPtrace => "CAP_SYS_PTRACE",
            Self::SysPacct => "CAP_SYS_PACCT", Self::SysAdmin => "CAP_SYS_ADMIN",
            Self::SysBoot => "CAP_SYS_BOOT", Self::SysNice => "CAP_SYS_NICE",
            Self::SysResource => "CAP_SYS_RESOURCE", Self::SysTime => "CAP_SYS_TIME",
            Self::SysTtyConfig => "CAP_SYS_TTY_CONFIG", Self::Mknod => "CAP_MKNOD",
            Self::Lease => "CAP_LEASE", Self::AuditWrite => "CAP_AUDIT_WRITE",
            Self::AuditControl => "CAP_AUDIT_CONTROL", Self::Setfcap => "CAP_SETFCAP",
            Self::MacOverride => "CAP_MAC_OVERRIDE", Self::MacAdmin => "CAP_MAC_ADMIN",
            Self::Syslog => "CAP_SYSLOG", Self::WakeAlarm => "CAP_WAKE_ALARM",
            Self::BlockSuspend => "CAP_BLOCK_SUSPEND", Self::AuditRead => "CAP_AUDIT_READ",
            Self::Perfmon => "CAP_PERFMON", Self::Bpf => "CAP_BPF",
            Self::CheckpointRestore => "CAP_CHECKPOINT_RESTORE",
        }
    }
}

impl serde::Serialize for LinuxCapability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Map an observed syscall name (from the event `args`) to the
/// capability it gates. One syscall can gate several capabilities
/// (e.g. `open` → `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`).
///
/// The table is the representative mapping from the capability map
/// Part 2 (SRC-13).
#[must_use]
pub fn syscall_to_capabilities(syscall: &str) -> &'static [LinuxCapability] {
    match syscall {
        "chown" | "fchown" | "lchown" | "fchownat" => &[LinuxCapability::Chown],
        "open" | "openat" | "openat2" | "creat" | "access" | "faccessat" | "faccessat2"
        | "readlink" | "readlinkat" => {
            &[LinuxCapability::DacOverride, LinuxCapability::DacReadSearch]
        }
        "chmod" | "fchmod" | "fchmodat" => &[LinuxCapability::Fowner, LinuxCapability::Fsetid],
        "utimensat" => &[LinuxCapability::Fowner],
        "kill" | "tgkill" | "tkill" | "pidfd_send_signal" => &[LinuxCapability::Kill],
        "setgid" | "setgroups" | "setregid" | "setresgid" | "setfsgid" => {
            &[LinuxCapability::Setgid]
        }
        "setuid" | "setreuid" | "setresuid" | "setfsuid" => &[LinuxCapability::Setuid],
        "capset" | "prctl" => &[LinuxCapability::Setpcap],
        "ioctl" => &[
            LinuxCapability::LinuxImmutable,
            LinuxCapability::SysTtyConfig,
        ],
        "vhangup" => &[LinuxCapability::SysTtyConfig],
        "bind" => &[LinuxCapability::NetBindService],
        "setsockopt" => &[LinuxCapability::NetAdmin, LinuxCapability::NetBroadcast],
        "socket" => &[LinuxCapability::NetRaw, LinuxCapability::NetAdmin],
        "mlock" | "mlockall" | "mlock2" | "mmap" => &[LinuxCapability::IpcLock],
        "shmctl" | "semctl" | "msgctl" => &[LinuxCapability::IpcOwner],
        "init_module" | "finit_module" | "delete_module" => &[LinuxCapability::SysModule],
        "iopl" | "ioperm" => &[LinuxCapability::SysRawio],
        "chroot" => &[LinuxCapability::SysChroot],
        "ptrace" | "process_vm_readv" | "process_vm_writev" | "userfaultfd" | "pidfd_getfd" => {
            &[LinuxCapability::SysPtrace]
        }
        "acct" => &[LinuxCapability::SysPacct],
        "mount" | "umount2" | "setns" | "unshare" | "quotactl" | "swapon" | "swapoff"
        | "pivot_root" | "sethostname" | "setdomainname" | "seccomp" | "io_uring_enter"
        | "quotactl_fd" | "lookup_dcookie" | "fanotify_init" | "fanotify_mark"
        | "io_uring_setup" | "io_uring_register" | "open_tree" | "move_mount" | "fsopen"
        | "fsconfig" | "fsmount" | "fspick" | "mount_setattr" => &[LinuxCapability::SysAdmin],
        "bpf" => &[LinuxCapability::Bpf, LinuxCapability::SysAdmin],
        "perf_event_open" => &[LinuxCapability::Perfmon, LinuxCapability::SysAdmin],
        "reboot" | "kexec_load" | "kexec_file_load" => &[LinuxCapability::SysBoot],
        "setpriority" | "sched_setscheduler" | "sched_setaffinity" | "sched_setparam"
        | "sched_setattr" | "nice" | "ioprio_set" => &[LinuxCapability::SysNice],
        "setrlimit" | "prlimit64" => &[LinuxCapability::SysResource],
        "open_by_handle_at" => &[LinuxCapability::DacReadSearch],
        "mknod" | "mknodat" => &[LinuxCapability::Mknod],
        "settimeofday" | "clock_settime" | "adjtimex" | "clock_adjtime" => {
            &[LinuxCapability::SysTime]
        }
        "setxattr" | "lsetxattr" | "fsetxattr" | "removexattr" | "lremovexattr"
        | "fremovexattr" => &[
            LinuxCapability::Setfcap,
            LinuxCapability::MacOverride,
            LinuxCapability::MacAdmin,
        ],
        "syslog" | "klogctl" => &[LinuxCapability::Syslog],
        "timerfd_create" => &[LinuxCapability::WakeAlarm],
        "epoll_ctl" => &[LinuxCapability::BlockSuspend],
        "fcntl" => &[LinuxCapability::Lease],
        "clone3" | "pidfd_open" | "kcmp" => &[LinuxCapability::CheckpointRestore],
        _ => &[],
    }
}

/// The closed set of all 41 capabilities, in canonical order.
#[rustfmt::skip]
pub const ALL_CAPABILITIES: [LinuxCapability; 41] = [
    LinuxCapability::Chown, LinuxCapability::DacOverride, LinuxCapability::DacReadSearch,
    LinuxCapability::Fowner, LinuxCapability::Fsetid, LinuxCapability::Kill,
    LinuxCapability::Setgid, LinuxCapability::Setuid, LinuxCapability::Setpcap,
    LinuxCapability::LinuxImmutable, LinuxCapability::NetBindService, LinuxCapability::NetBroadcast,
    LinuxCapability::NetAdmin, LinuxCapability::NetRaw, LinuxCapability::IpcLock,
    LinuxCapability::IpcOwner, LinuxCapability::SysModule, LinuxCapability::SysRawio,
    LinuxCapability::SysChroot, LinuxCapability::SysPtrace, LinuxCapability::SysPacct,
    LinuxCapability::SysAdmin, LinuxCapability::SysBoot, LinuxCapability::SysNice,
    LinuxCapability::SysResource, LinuxCapability::SysTime, LinuxCapability::SysTtyConfig,
    LinuxCapability::Mknod, LinuxCapability::Lease, LinuxCapability::AuditWrite,
    LinuxCapability::AuditControl, LinuxCapability::Setfcap, LinuxCapability::MacOverride,
    LinuxCapability::MacAdmin, LinuxCapability::Syslog, LinuxCapability::WakeAlarm,
    LinuxCapability::BlockSuspend, LinuxCapability::AuditRead, LinuxCapability::Perfmon,
    LinuxCapability::Bpf, LinuxCapability::CheckpointRestore,
];

/// The capabilities with at least one observed *successful* use of a
/// gated syscall. Capabilities not in this set are candidates for
/// `CapabilityBoundingSet=~CAP_X`.
///
/// The input is the observer's events. Capability-relevant events
/// (`Other("capability")`, args carry the syscall name) map directly
/// via [`syscall_to_capabilities`]; address-family `socket` events
/// additionally contribute `CAP_NET_RAW`/`CAP_NET_ADMIN` when the
/// socket type is raw or packet (a successfully created raw socket is
/// the observable use of those capabilities).
/// The capabilities that inherently gate a syscall: any successful
/// invocation of the syscall requires the capability. Unprivileged
/// processes cannot call these without the kernel granting the
/// capability (unlike `openat` or `mmap`, which succeed unprivileged
/// on normal resources without `CAP_DAC_OVERRIDE` or `CAP_IPC_LOCK`).
#[must_use]
pub fn syscall_to_inherent_capabilities(syscall: &str) -> &'static [LinuxCapability] {
    match syscall {
        "mount" | "umount2" | "setns" | "unshare" | "quotactl" | "swapon" | "swapoff"
        | "pivot_root" | "sethostname" | "setdomainname" | "quotactl_fd" | "lookup_dcookie"
        | "fanotify_init" | "open_tree" | "move_mount" | "fsopen" | "fsconfig" | "fsmount"
        | "fspick" | "mount_setattr" => &[LinuxCapability::SysAdmin],
        "setgroups" => &[LinuxCapability::Setgid],
        "bpf" => &[LinuxCapability::Bpf, LinuxCapability::SysAdmin],
        "perf_event_open" => &[LinuxCapability::Perfmon, LinuxCapability::SysAdmin],
        "mknod" | "mknodat" => &[LinuxCapability::Mknod],
        "chroot" => &[LinuxCapability::SysChroot],
        "reboot" | "kexec_load" | "kexec_file_load" => &[LinuxCapability::SysBoot],
        "init_module" | "finit_module" | "delete_module" => &[LinuxCapability::SysModule],
        "iopl" | "ioperm" => &[LinuxCapability::SysRawio],
        "acct" => &[LinuxCapability::SysPacct],
        "syslog" | "klogctl" => &[LinuxCapability::Syslog],
        "settimeofday" | "clock_settime" | "adjtimex" | "clock_adjtime" => {
            &[LinuxCapability::SysTime]
        }
        "ptrace" | "process_vm_readv" | "process_vm_writev" => &[LinuxCapability::SysPtrace],
        "capset" => &[LinuxCapability::Setpcap],
        "vhangup" => &[LinuxCapability::SysTtyConfig],
        "open_by_handle_at" => &[LinuxCapability::DacReadSearch],
        _ => &[],
    }
}

fn collect_capabilities<F>(events: &[ObservedEvent], map_fn: F) -> Vec<LinuxCapability>
where
    F: Fn(&str) -> &'static [LinuxCapability],
{
    let mut caps: Vec<LinuxCapability> = Vec::new();
    for event in events {
        if event.outcome() == crate::fixture::EventOutcome::Error
            || event.outcome() == crate::fixture::EventOutcome::Interrupted
        {
            continue;
        }
        if event.address_family() == crate::fixture::AddressFamily::Other("capability") {
            let syscall = event.args().split(' ').next().unwrap_or("");
            for cap in map_fn(syscall) {
                if !caps.contains(cap) {
                    caps.push(*cap);
                }
            }
        } else if event.address_family() == crate::fixture::AddressFamily::Packet
            || (event.args().starts_with("socket") && event.args().contains("type=raw"))
        {
            for cap in [LinuxCapability::NetRaw, LinuxCapability::NetAdmin] {
                if !caps.contains(&cap) {
                    caps.push(cap);
                }
            }
        }
    }
    caps.sort_unstable();
    caps
}

/// The capabilities with at least one observed *successful* use of a
/// gated syscall. Capabilities not in this set are candidates for
/// `CapabilityBoundingSet=~CAP_X`.
#[must_use]
pub fn successfully_used_capabilities(events: &[ObservedEvent]) -> Vec<LinuxCapability> {
    collect_capabilities(events, syscall_to_capabilities)
}

/// The provisional `CapabilityBoundingSet=` candidate: the
/// capabilities with no observed successful use, in canonical order.
///
/// Absence of use is not proof of non-need — the candidate is
/// provisional, exactly like the address-family candidate.
#[must_use]
pub fn recommend_capability_bounding_set(events: &[ObservedEvent]) -> Vec<LinuxCapability> {
    let used = successfully_used_capabilities(events);
    ALL_CAPABILITIES
        .iter()
        .copied()
        .filter(|cap| !used.contains(cap))
        .collect()
}

/// The `AmbientCapabilities=` candidate: capabilities the service
/// provably required to perform inherently privileged operations.
///
/// Unlike the bounding set (which drops capabilities with no
/// observed interaction), the ambient grant list only re-grants
/// capabilities whose gated operations cannot succeed unprivileged.
#[must_use]
pub fn recommend_ambient_capabilities(events: &[ObservedEvent]) -> Vec<LinuxCapability> {
    collect_capabilities(events, syscall_to_inherent_capabilities)
}

/// The canonical directive name for the ambient-capability candidate.
pub const AMBIENT_CAPABILITIES_DIRECTIVE: &str = "AmbientCapabilities";

/// The source ID the capability recommendation stamps on its finding.
/// The evidence is the observer's (SRC-12); the recommendation is
/// derived from it.
pub const CAPABILITY_SOURCE_ID: SourceId = SourceId::from_static("SRC-12");

/// The canonical directive name for the capability candidate.
pub const CAPABILITY_DIRECTIVE: &str = "CapabilityBoundingSet";

/// Returns true if the observed event represents capability evidence:
/// either a capability-gated syscall (`Other("capability")`), packet socket, or a raw socket creation.
#[must_use]
pub fn is_capability_event(event: &ObservedEvent) -> bool {
    event.address_family() == crate::fixture::AddressFamily::Packet
        || (event.args().starts_with("socket") && event.args().contains("type=raw"))
        || (event.address_family() == crate::fixture::AddressFamily::Other("capability")
            && !syscall_to_capabilities(event.args().split(' ').next().unwrap_or("")).is_empty())
}
