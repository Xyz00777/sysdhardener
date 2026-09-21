//! The typed `ObservedEvent` value.
//!
//! Extracted from `fixture.rs` to keep that module under the 250
//! pure-LOC ceiling. An observed event is one captured syscall (or
//! one fixture entry) with its typed labels and, for live
//! observation, the producing process's pid and cgroup.

use crate::fixture::{AddressFamily, EventOutcome};
use crate::source_id::SourceId;
use crate::timestamp::FixtureTimestamp;

/// A single observed event, already typed and validated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservedEvent {
    source_id: SourceId,
    event_id: String,
    timestamp: FixtureTimestamp,
    address_family: AddressFamily,
    outcome: EventOutcome,
    args: String,
    /// The pid of the process that produced the event, when the
    /// observation is live. Fixture events carry `None`; the live
    /// observer stamps the tracee's pid so the detailed report can
    /// attribute each event to a process in the service tree.
    pid: Option<i32>,
    /// The cgroup path of the process that produced the event, when
    /// the observation is live (read from `/proc/<pid>/cgroup`).
    /// Fixture events carry `None`; the live observer stamps the
    /// tracee's cgroup so the report can attribute events to the
    /// service's cgroup (the production observer's attribution unit).
    cgroup: Option<String>,
}

impl ObservedEvent {
    /// Construct an observed event from typed values. Public so the
    /// live observer (a sibling crate) can build events from captured
    /// syscalls without going through the fixture wire format; the
    /// fixture parser uses the same constructor internally.
    #[must_use]
    pub const fn new(
        source_id: SourceId,
        event_id: String,
        timestamp: FixtureTimestamp,
        address_family: AddressFamily,
        outcome: EventOutcome,
        args: String,
    ) -> Self {
        Self::new_with_pid_cgroup(
            source_id,
            event_id,
            timestamp,
            address_family,
            outcome,
            args,
            None,
            None,
        )
    }

    /// Construct an observed event from typed values, stamped with
    /// the producing process's pid. Used by the live observer so the
    /// detailed report can attribute events across the service tree.
    #[allow(
        clippy::too_many_arguments,
        reason = "event shape is fixed by the wire contract"
    )]
    #[must_use]
    pub const fn new_with_pid(
        source_id: SourceId,
        event_id: String,
        timestamp: FixtureTimestamp,
        address_family: AddressFamily,
        outcome: EventOutcome,
        args: String,
        pid: Option<i32>,
    ) -> Self {
        Self::new_with_pid_cgroup(
            source_id,
            event_id,
            timestamp,
            address_family,
            outcome,
            args,
            pid,
            None,
        )
    }

    /// Construct an observed event from typed values, stamped with
    /// the producing process's pid and cgroup. Used by the live
    /// observer so the report can attribute events across the service
    /// tree and to the service's cgroup.
    #[allow(
        clippy::too_many_arguments,
        reason = "event shape is fixed by the wire contract"
    )]
    #[must_use]
    pub const fn new_with_pid_cgroup(
        source_id: SourceId,
        event_id: String,
        timestamp: FixtureTimestamp,
        address_family: AddressFamily,
        outcome: EventOutcome,
        args: String,
        pid: Option<i32>,
        cgroup: Option<String>,
    ) -> Self {
        Self {
            source_id,
            event_id,
            timestamp,
            address_family,
            outcome,
            args,
            pid,
            cgroup,
        }
    }

    /// The pid of the process that produced this event, when known.
    /// `None` for fixture events and for live events whose pid could
    /// not be captured.
    #[must_use]
    pub const fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// The cgroup path of the process that produced this event, when
    /// known. `None` for fixture events and for live events whose
    /// cgroup could not be read.
    #[must_use]
    pub fn cgroup(&self) -> Option<&str> {
        self.cgroup.as_deref()
    }

    /// Source registry ID of the observation.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Stable semantic identifier carried on the wire. The
    /// boundary guarantees this is non-empty and unique within
    /// the parent fixture's `events[]`.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Unix-epoch-millisecond timestamp of the event.
    #[must_use]
    pub const fn timestamp_unix_ms(&self) -> i64 {
        self.timestamp.unix_ms()
    }

    /// Address family observed.
    #[must_use]
    pub const fn address_family(&self) -> AddressFamily {
        self.address_family
    }

    /// Outcome of the event.
    #[must_use]
    pub const fn outcome(&self) -> EventOutcome {
        self.outcome
    }

    /// Raw arguments string carried on the event. Treated as opaque data.
    #[must_use]
    pub fn args(&self) -> &str {
        &self.args
    }
}
