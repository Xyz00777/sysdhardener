# Research and Evidence Reference

This document combines the authoritative source registry and the research grounding for sysdhardener's syscall and capability mappings.

## Source registry

`SRC-NN` identifiers are stable and reused by code, tests, and reports.

| ID | Source | Class | Locator / note | Status |
| --- | --- | --- | --- | --- |
| SRC-01 | `systemd.service(5)` | official systemd | freedesktop/systemd upstream | verified |
| SRC-02 | `systemd.resource-control(5)` | official systemd | freedesktop/systemd upstream | verified |
| SRC-03 | `systemd.exec.xml` | systemd source | systemd upstream | verified |
| SRC-04 | systemd seccomp encoding | systemd source | `src/shared/seccomp-util.c` | verified |
| SRC-05 | `io_uring_enter(2)` | Linux man pages | man7.org | verified |
| SRC-06 | `mmap(2)` | Linux man pages | man7.org | verified |
| SRC-07 | `openat2(2)` | Linux man pages | man7.org | verified |
| SRC-08 | `perf_event_open(2)` | Linux man pages | man7.org | verified |
| SRC-09 | `seccomp(2)` | Linux man pages | man7.org | verified |
| SRC-10 | `path_resolution(7)` | Linux man pages | man7.org | verified |
| SRC-11 | Kernel trace events | kernel documentation | kernel.org | verified |
| SRC-12 | ptrace observer | repository implementation | live observer | verified |
| SRC-13 | `capabilities(7)` | Linux man pages | man7.org | verified |
| SRC-14 | eBPF observer | repository implementation | live cgroup capture | verified |

## Implemented syscall-to-hardening coverage

### 1. Network Address Families

The observer covers socket-family operations. `RestrictAddressFamilies=` is the
primary directive because it encodes the observed address-family set.

| Syscall/family | Capability relevance | Directive |
| --- | --- | --- |
| `socket(AF_UNIX)` | none | `RestrictAddressFamilies=AF_UNIX` |
| `socket(AF_INET/AF_INET6)` | raw sockets may require `CAP_NET_RAW` | `RestrictAddressFamilies=` plus capability handling |
| `socket(AF_NETLINK)` | route changes may require `CAP_NET_ADMIN` | `RestrictAddressFamilies=AF_NETLINK` |
| `socket(AF_PACKET)` | `CAP_NET_RAW` | `RestrictAddressFamilies=AF_PACKET` |
| `bind` | ports below 1024 may require `CAP_NET_BIND_SERVICE` | capability bounding set |
| `connect`, `accept`, `sendto`, `recvfrom` | not independently capability-gated | family evidence only |

### 2. Complete Linux Capability Registry and Version Mapping

sysdhardener tracks the full closed set of 41 Linux capabilities (`ALL_CAPABILITIES` in `crates/sysdhardener-core/src/capability.rs`, SRC-13). Systemd introduced directive-level control over capabilities in:
- `CapabilityBoundingSet=` since **systemd v1** (drops unneeded capabilities via `~CAP_X`)
- `AmbientCapabilities=` since **systemd v229** (preserves provably required non-root capabilities)

The table below catalogs every capability, the Linux kernel and systemd version that introduced it, and the syscalls mapped by the observer:

| Capability | Linux Kernel | systemd | Key Gated Syscalls | Inherent vs Discretionary |
| --- | --- | --- | --- | --- |
| `CAP_CHOWN` | 2.2 | 1 | `chown`, `fchown`, `lchown`, `fchownat` | discretionary |
| `CAP_DAC_OVERRIDE` | 2.2 | 1 | `open`, `openat`, `creat`, `access`, `faccessat` | discretionary |
| `CAP_DAC_READ_SEARCH` | 2.2 | 1 | `open_by_handle_at`, `readlink`, `readlinkat` | discretionary (`open_by_handle_at` inherent) |
| `CAP_FOWNER` | 2.2 | 1 | `chmod`, `fchmod`, `fchmodat`, `utimensat` | discretionary |
| `CAP_FSETID` | 2.2 | 1 | `chmod`, `fchmod`, `fchmodat` (setuid/gid bits) | discretionary |
| `CAP_KILL` | 2.2 | 1 | `kill`, `tgkill`, `tkill`, `pidfd_send_signal` | discretionary |
| `CAP_SETGID` | 2.2 | 1 | `setgid`, `setgroups`, `setregid`, `setresgid`, `setfsgid` | discretionary (`setgroups` inherent) |
| `CAP_SETUID` | 2.2 | 1 | `setuid`, `setreuid`, `setresuid`, `setfsuid` | discretionary |
| `CAP_SETPCAP` | 2.2 | 1 | `capset`, `prctl` | inherent (`capset`) |
| `CAP_LINUX_IMMUTABLE` | 2.2 | 1 | `ioctl` (`FS_IOC_SETFLAGS`) | discretionary |
| `CAP_NET_BIND_SERVICE`| 2.2 | 1 | `bind` (ports < 1024) | discretionary |
| `CAP_NET_BROADCAST` | 2.2 | 1 | `setsockopt` (`SO_BROADCAST`) | discretionary |
| `CAP_NET_ADMIN` | 2.2 | 1 | `setsockopt`, `socket(AF_NETLINK)`, interface config | discretionary |
| `CAP_NET_RAW` | 2.2 | 1 | `socket(SOCK_RAW)`, `socket(AF_PACKET)` | discretionary |
| `CAP_IPC_LOCK` | 2.2 | 1 | `mlock`, `mlockall`, `mlock2`, `mmap(MAP_LOCKED)` | discretionary |
| `CAP_IPC_OWNER` | 2.2 | 1 | `shmctl`, `semctl`, `msgctl` | discretionary |
| `CAP_SYS_MODULE` | 2.2 | 1 | `init_module`, `finit_module`, `delete_module` | inherent |
| `CAP_SYS_RAWIO` | 2.2 | 1 | `iopl`, `ioperm`, direct `/dev/mem` | inherent |
| `CAP_SYS_CHROOT` | 2.2 | 1 | `chroot` | inherent |
| `CAP_SYS_PTRACE` | 2.2 | 1 | `ptrace`, `process_vm_readv`, `process_vm_writev`, `userfaultfd`, `pidfd_getfd` | discretionary / inherent |
| `CAP_SYS_PACCT` | 2.2 | 1 | `acct` | inherent |
| `CAP_SYS_ADMIN` | 2.2 | 1 | `mount`, `umount2`, `setns`, `unshare`, `pivot_root`, `swapon`, `quotactl`, `open_tree`, `fsmount` | inherent |
| `CAP_SYS_BOOT` | 2.2 | 1 | `reboot`, `kexec_load`, `kexec_file_load` | inherent |
| `CAP_SYS_NICE` | 2.2 | 1 | `setpriority`, `sched_setscheduler`, `sched_setaffinity`, `nice`, `ioprio_set` | discretionary |
| `CAP_SYS_RESOURCE` | 2.2 | 1 | `setrlimit`, `prlimit64`, `mknod` | discretionary |
| `CAP_SYS_TIME` | 2.2 | 1 | `settimeofday`, `clock_settime`, `adjtimex`, `clock_adjtime` | inherent |
| `CAP_SYS_TTY_CONFIG` | 2.2 | 1 | `ioctl(TIOCSTI)`, `vhangup` | inherent (`vhangup`) |
| `CAP_MKNOD` | 2.4 | 1 | `mknod`, `mknodat` | inherent |
| `CAP_LEASE` | 2.4 | 1 | `fcntl(F_SETLEASE)` | discretionary |
| `CAP_AUDIT_WRITE` | 2.6.11 | 1 | Netlink audit socket send | discretionary |
| `CAP_AUDIT_CONTROL` | 2.6.11 | 1 | Netlink audit configuration | discretionary |
| `CAP_SETFCAP` | 2.6.24 | 1 | `setxattr`, `lsetxattr`, `fsetxattr` (`security.capability`) | discretionary |
| `CAP_MAC_OVERRIDE` | 2.6.25 | 1 | SMACK / SELinux policy overrides | discretionary |
| `CAP_MAC_ADMIN` | 2.6.25 | 1 | SMACK / SELinux policy manipulation | discretionary |
| `CAP_SYSLOG` | 2.6.37 | 1 | `syslog`, `klogctl`, `/dev/kmsg` | inherent |
| `CAP_WAKE_ALARM` | 3.0 | 1 | `timerfd_create(CLOCK_BOOTTIME_ALARM)` | discretionary |
| `CAP_BLOCK_SUSPEND` | 3.5 | 1 | `epoll_ctl(EPOLLWAKEUP)` | discretionary |
| `CAP_AUDIT_READ` | 3.16 | 219 | Netlink audit read operations | discretionary |
| `CAP_PERFMON` | 5.8 | 247 | `perf_event_open` | inherent (`perf_event_open`) |
| `CAP_BPF` | 5.8 | 247 | `bpf` | inherent (`bpf`) |
| `CAP_CHECKPOINT_RESTORE` | 5.9 | 248 | `clone3`, `pidfd_open`, `kcmp` | discretionary |

### 3. Syscall Boundary Semantics vs. Kernel-Internal LSM Auditing

- **Syscall-boundary observation:** sysdhardener observes userspace-to-kernel transitions. Absence of a gated syscall provides reproducible evidence that the corresponding capability was not used.
- **Inherent vs. Discretionary:** Syscalls classified as *inherent* (such as `mount`, `swapon`, `reboot`, or `init_module`) unconditionally fail when invoked without the capability. Syscalls classified as *discretionary* (such as `openat` or `bind`) only require the capability if DAC or resource restrictions demand it.
- **LSM distinction:** Tracing at the syscall boundary does not execute inside internal kernel LSM authorization hooks (`security_capable()`). It operates at the entry/exit boundary to guarantee zero system breakage without requiring custom in-kernel security modules.

## Known observation limits

- Non-root execution has degraded visibility.
- Root does not guarantee complete observation.
- Ptrace syscall-stop delivery is kernel-dependent; undelivered calls such as `getpeername` and `setpriority` are observation gaps, not proof of non-use.
- eBPF sockaddr hooks observe attempts before return values are known. `Unknown` therefore means attempted with outcome unavailable, not failure.
- The current implementation is strictly syscall-driven. Supplementary runtime evidence (e.g. LSM hooks or path resolution) remains an open academic research question.
- Profiling is strictly on-demand via `ExecStart=` launch (`observe`) or direct side-channel attachment (`attach` / eBPF cgroup); permanent background daemonization is intentionally out of scope.

