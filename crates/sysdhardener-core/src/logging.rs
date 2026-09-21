//! Bounded raw-event TRACE logging.
//!
//! [`RawEventLog`] is the single place in the crate that emits
//! individual observed events. It is deliberately separated from the
//! analysis seam so that:
//!
//! - raw-event emission is always **opt-in and bounded**: nothing is
//!   emitted once the configured cap is reached, and a single
//!   truncation line reports how many were dropped;
//! - every raw event carries stable machine fields (`event_index`,
//!   `event_id`, `event_family`, `event_outcome`,
//!   `event_timestamp_unix_ms`, `event_source_id`, `event_args`) as
//!   data, never interpolated into the message;
//! - the level is fixed at `TRACE`, so no default configuration ever
//!   surfaces individual events (never at DEBUG or higher).
//!
//! This module is pure with respect to the evidence pipeline: it never
//! reads the fixture, computes aggregates, or produces report output.
//! It only forwards events to `tracing` for whatever writer the
//! process has installed (stderr in the CLI, an injected writer in
//! tests).

use crate::observed_event::ObservedEvent;

/// Bounded budget for raw observed-event TRACE lines.
///
/// One instance is created per analysis run, seeded with the caller's
/// limit. `record` emits the event only while the budget is not
/// exhausted; once exhausted it only marks truncation. `finish` emits
/// a single truncation line when the cap actually dropped events.
#[derive(Debug)]
pub struct RawEventLog {
    /// Maximum number of raw events to emit for the run.
    cap: usize,
    /// Number of raw events already emitted.
    logged: usize,
    /// Whether any raw event was suppressed because the cap was hit.
    truncated: bool,
}

impl RawEventLog {
    /// Create a fresh budget. `cap == 0` suppresses every raw event
    /// while still reporting the full total via the truncation line.
    #[must_use]
    pub const fn new(cap: usize) -> Self {
        Self {
            cap,
            logged: 0,
            truncated: false,
        }
    }

    /// Forward one raw event to `tracing` at `TRACE` while the budget
    /// remains, otherwise mark the run as truncated.
    ///
    /// `index` is the position of the event in the fixture's `events[]`
    /// wire order; the fields are stable machine data.
    pub fn record(&mut self, index: usize, event: &ObservedEvent) {
        if self.logged < self.cap {
            emit(index, event);
            self.logged += 1;
        } else {
            self.truncated = true;
        }
    }

    /// Emit the single truncation line, if any raw events were dropped.
    ///
    /// `total` is the number of events the run saw, so the line can
    /// report how much of the raw stream was suppressed.
    pub fn finish(&self, total: usize) {
        if self.truncated {
            tracing::trace!(
                target: "sysdhardener.raw_event",
                truncated = true,
                logged = self.logged,
                total,
                cap = self.cap,
                "raw event log truncated"
            );
        }
    }
}

/// Emit one raw observed event with stable machine fields.
fn emit(index: usize, event: &ObservedEvent) {
    tracing::trace!(
        target: "sysdhardener.raw_event",
        event_index = index,
        event_id = %event.event_id(),
        event_family = ?event.address_family(),
        event_outcome = ?event.outcome(),
        event_timestamp_unix_ms = event.timestamp_unix_ms(),
        event_source_id = %event.source_id().as_str(),
        event_args = %event.args(),
        "raw observed event"
    );
}
