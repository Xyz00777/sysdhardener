//! Exit status of the command directly spawned by the observer.

#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(super) marks sibling-module access within this private module"
)]

/// The target process's final status, distinct from any traced child status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    /// The process exited normally with this code.
    Exited(i32),
    /// The process was terminated by this signal number.
    Signaled(i32),
    /// The observation stopped before the target's termination was observed.
    Unknown,
}

impl TargetStatus {
    pub(super) const fn from_wait_status(status: libc::c_int) -> Self {
        if libc::WIFEXITED(status) {
            Self::Exited(libc::WEXITSTATUS(status))
        } else {
            Self::Signaled(libc::WTERMSIG(status))
        }
    }
}

/// Events and the status of the directly spawned target process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationResult {
    events: Vec<sysdhardener_core::ObservedEvent>,
    target_status: TargetStatus,
}

pub(super) struct TraceCapture {
    pub(super) events: Vec<sysdhardener_core::ObservedEvent>,
    pub(super) main_status: TargetStatus,
}

impl ObservationResult {
    pub(super) const fn new(
        events: Vec<sysdhardener_core::ObservedEvent>,
        target_status: TargetStatus,
    ) -> Self {
        Self {
            events,
            target_status,
        }
    }

    /// Captured address-family syscall events from the process tree.
    #[must_use]
    pub fn events(&self) -> &[sysdhardener_core::ObservedEvent] {
        &self.events
    }

    /// Final status of the main spawned process, or [`TargetStatus::Unknown`]
    /// when observation ended before its termination was seen.
    #[must_use]
    pub const fn target_status(&self) -> TargetStatus {
        self.target_status
    }

    /// Consume the result and return its captured events.
    #[must_use]
    pub fn into_events(self) -> Vec<sysdhardener_core::ObservedEvent> {
        self.events
    }
}
