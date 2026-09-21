//! The fixture-backed [`EventSource`] implementation.
//!
//! This is the **only** [`EventSource`] implementation in the
//! deterministic slice. It reads a single-envelope JSON fixture,
//! runs it through the boundary parser in [`crate::parse_fixture_v1`],
//! and emits the parsed events in wire order. The source never reads
//! wall-clock, randomness, JSONL streams, target units, or process
//! state; every observable value originates in the fixture file.

use std::fs;

use crate::CoverageQuality;
use crate::error::Error;
use crate::fixture::{Fixture, parse_fixture_v1};
use crate::ports::EventSource;

/// The single [`EventSource`] implementation in the workspace.
///
/// The source owns the raw fixture bytes. The boundary parse runs
/// on construction so the typed [`Fixture`] is materialized once
/// and `collect` simply clones the event vector. The source
/// therefore does no I/O at `collect` time, never sleeps, and
/// never touches the wall clock.
#[derive(Debug, Clone)]
pub struct FixtureEventSource {
    fixture: Fixture,
}

impl FixtureEventSource {
    /// Load a fixture from a file path.
    ///
    /// # Errors
    /// Returns [`Error::Io`] when the file cannot be read; the typed
    /// discriminant carries a stable description and never a raw path.
    /// Returns the same boundary [`Error`] variants as
    /// [`parse_fixture_v1`] when the file is malformed.
    pub fn from_path(path: &str) -> Result<Self, Error> {
        let bytes: Vec<u8> = fs::read(path).map_err(|e| Error::Io {
            context: format!("failed to read fixture path: {e}"),
        })?;
        Self::from_bytes(&bytes)
    }

    /// Load a fixture from a byte slice.
    ///
    /// # Errors
    /// Returns the same boundary [`Error`] variants as
    /// [`parse_fixture_v1`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let fixture: Fixture = parse_fixture_v1(bytes)?;
        Ok(Self { fixture })
    }

    /// Coverage quality tag carried on the envelope.
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.fixture.coverage()
    }

    /// Declared `seen_events` count. The boundary guarantees this
    /// equals the number of events returned by `collect`.
    #[must_use]
    pub const fn seen_events(&self) -> u32 {
        self.fixture.seen_events()
    }

    /// Declared `dropped_events` count. The boundary guarantees
    /// this is at most `seen_events`.
    #[must_use]
    pub const fn dropped_events(&self) -> u32 {
        self.fixture.dropped_events()
    }

    /// First timestamp declared on the envelope.
    #[must_use]
    pub const fn first_timestamp_unix_ms(&self) -> i64 {
        self.fixture.first_timestamp_unix_ms()
    }

    /// Last timestamp declared on the envelope.
    #[must_use]
    pub const fn last_timestamp_unix_ms(&self) -> i64 {
        self.fixture.last_timestamp_unix_ms()
    }

    /// The fixture identifier declared on the envelope.
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        self.fixture.fixture_id()
    }
}

impl EventSource for FixtureEventSource {
    fn collect(&self) -> Result<Vec<crate::observed_event::ObservedEvent>, Error> {
        Ok(self.fixture.events().to_vec())
    }
}
