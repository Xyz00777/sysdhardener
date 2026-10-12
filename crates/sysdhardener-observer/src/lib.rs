//! Live syscall observer for sysdhardener.
//!
//! The observer is the missing half of the product: it attaches to a
//! real target process, captures its address-family syscalls, and
//! produces the typed [`ObservedEvent`] stream the deterministic
//! analysis engine consumes. It implements the [`EventSource`] port,
//! so the engine's input surface is unchanged whether the events come
//! from a fixture file or from a live process.
//!
//! # Mechanism
//!
//! The first mechanism is **ptrace-based capture** (the deferred
//! interposition comparison's "transient launch" mode): the observer
//! forks the target under `PTRACE_TRACEME`, single-steps through
//! syscall entry/exit stops, reads the syscall number and arguments
//! from the register file, and decodes the socket-family syscalls
//! (`socket`, `connect`, `bind`, `accept`, `sendto`, `recvfrom`,
//! `getsockname`, `getpeername`) into typed events. This works
//! unprivileged and is testable in the current environment; the
//! production-favored cgroup-attached eBPF observer (deferred doc
//! option 1) remains future work that needs root + BPF.
//!
//! # Safety boundary
//!
//! The observer only reads the target's syscalls. It never injects
//! code, never modifies the target's memory, never applies hardening,
//! and never writes host configuration. The target runs to completion
//! under observation; the observer reports what it saw.
//!
//! # Unsafe
//!
//! This crate is the one place in the workspace that calls raw libc
//! (`ptrace`, `waitpid`, `PEEKDATA`). The unsafe is confined to the
//! [`capture`] module; the decode and syscall modules are safe.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod arch;
mod attach;
mod capture;
mod decode;
mod fs_trace;
mod ptrace_abi;
mod signal;
mod spawn;
mod syscall;
mod tracee;

pub use attach::{observe_pid, observe_pid_with_duration, systemd_unit_from_cgroup};
pub use capture::{ObserveError, PtraceObserver, observe_command, observe_command_with_status};
pub use decode::{
    DecodedSyscall, OBSERVER_SOURCE_ID, decode_syscall, decode_syscall_indexed,
    decode_syscall_indexed_fs,
};
pub use syscall::{KNOWN_UNDELIVERED_SYSCALLS, SyscallNumber, syscall_number_from_regs};
mod process_status;
pub use process_status::{ObservationResult, TargetStatus};
