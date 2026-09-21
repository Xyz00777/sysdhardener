//! Live-observer envelope construction and event-ID uniqueness
//! validation.
//!
//! [`Fixture::from_events`] and [`check_unique_event_ids`] live here
//! (not in `fixture.rs`) to keep that module under the 250 pure-LOC
//! ceiling; the observer crate consumes the constructor to wrap
//! captured events into the envelope shape the aggregator expects.

// `pub(crate)` items inside a private module trip
// `redundant_pub_crate`; the items are crate-visible by
// construction and the explicit marker is intentional for the
// helper module's contract.
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) markers document the helper module's crate-local intent"
)]

use std::collections::HashMap;

use crate::error::Error;
use crate::fixture::{CoverageQuality, Fixture};
use crate::observed_event::ObservedEvent;
use crate::schema::SchemaVersion;
use crate::timestamp::FixtureTimestamp;

impl Fixture {
    /// Build a fixture from a live-observed event stream. The live
    /// observer (sibling crate) produces typed events directly; this
    /// constructor wraps them in the envelope shape the aggregator
    /// consumes, with the window derived from the event timestamps
    /// and coverage `Unknown` (the observer cannot claim completeness;
    /// that is the engine's composition with visibility).
    #[must_use]
    pub fn from_events(events: Vec<ObservedEvent>) -> Self {
        let first: i64 = events
            .iter()
            .map(ObservedEvent::timestamp_unix_ms)
            .min()
            .unwrap_or(0);
        let last: i64 = events
            .iter()
            .map(ObservedEvent::timestamp_unix_ms)
            .max()
            .unwrap_or(0);
        let seen: u32 = u32::try_from(events.len()).unwrap_or(u32::MAX);
        Self {
            schema_version: SchemaVersion::v1_fixture(),
            id: "live-observer".to_owned(),
            first_timestamp: FixtureTimestamp::from_raw_checked(first),
            last_timestamp: FixtureTimestamp::from_raw_checked(last),
            coverage: CoverageQuality::Unknown,
            seen_events: seen,
            dropped_events: 0,
            events,
        }
    }

    /// Return the deduplicated, sorted pids of processes in the fixture.
    #[must_use]
    pub fn observed_pids(&self) -> Vec<i32> {
        let mut pids: Vec<i32> = self.events.iter().filter_map(ObservedEvent::pid).collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    /// Return the deduplicated, sorted cgroup paths of processes in the fixture.
    #[must_use]
    pub fn observed_cgroups(&self) -> Vec<String> {
        let mut cgroups: Vec<String> = self
            .events
            .iter()
            .filter_map(|e| e.cgroup().map(ToOwned::to_owned))
            .collect();
        cgroups.sort_unstable();
        cgroups.dedup();
        cgroups
    }
}

/// Enforce unique `event_id` values within a single fixture.
///
/// The pass is single-scan O(n): the first occurrence index of each
/// `event_id` is remembered, and every later duplicate pair is
/// considered; the pair whose *first* occurrence is earliest wins.
/// This reproduces the nested-loop contract exactly, so the reported
/// `(first_index, second_index)` values are unchanged for every input.
pub(crate) fn check_unique_event_ids(events: &[ObservedEvent]) -> Result<(), Error> {
    let mut first_seen: HashMap<&str, u32> = HashMap::with_capacity(events.len());
    let mut best_pair: Option<(u32, u32, &str)> = None;
    for (index_u32, event) in (0_u32..).zip(events) {
        if let Some(first_index) = first_seen.get(event.event_id()).copied() {
            let replace = match best_pair {
                Some((best_first, _, _)) => first_index < best_first,
                None => true,
            };
            if replace {
                best_pair = Some((first_index, index_u32, event.event_id()));
            }
        } else {
            first_seen.insert(event.event_id(), index_u32);
        }
    }
    if let Some((first_index, second_index, event_id)) = best_pair {
        return Err(Error::EventIdDuplicate {
            event_id: event_id.to_owned(),
            first_index,
            second_index,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{AddressFamily, EventOutcome};
    use crate::source_id::SourceId;

    #[test]
    fn from_events_computes_window_from_min_and_max_timestamps() {
        let e1 = ObservedEvent::new(
            SourceId::from_static("SRC-01"),
            "e1".to_owned(),
            FixtureTimestamp::from_raw_checked(1000),
            AddressFamily::Unix,
            EventOutcome::Success,
            "args".to_owned(),
        );
        let e2 = ObservedEvent::new(
            SourceId::from_static("SRC-01"),
            "e2".to_owned(),
            FixtureTimestamp::from_raw_checked(500),
            AddressFamily::Unix,
            EventOutcome::Success,
            "args".to_owned(),
        );
        let fixture = Fixture::from_events(vec![e1, e2]);
        assert_eq!(fixture.first_timestamp_unix_ms(), 500);
        assert_eq!(fixture.last_timestamp_unix_ms(), 1000);
    }
}
