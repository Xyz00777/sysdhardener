//! Fixture envelope v1: private wire DTO + public typed values.
//!
//! The wire DTO ([`FixtureWireV1`]) is private and never escapes the
//! crate; on success it is converted into the public [`Fixture`]
//! value, which uses the typed newtypes. After conversion the raw
//! wire shape is dropped.

use serde::Serialize;

use crate::error::Error;
use crate::fixture_events::check_unique_event_ids;
use crate::fixture_wire::{FixtureWireV1, map_serde_error};
use crate::observed_event::ObservedEvent;
use crate::ports::Capability;
use crate::schema::SchemaVersion;
use crate::source_id::SourceId;
use crate::timestamp::{FixtureTimestamp, check_fixture_window};

/// Address family observed for a single event. The wire tags are an
/// explicitly closed set; unknown tags fail at the boundary with
/// [`Error::AddressFamilyUnknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AddressFamily {
    /// `AF_UNIX` — local domain sockets.
    Unix,
    /// `AF_INET` — IPv4 sockets.
    Inet,
    /// `AF_INET6` — IPv6 sockets.
    Inet6,
    /// `AF_NETLINK` — netlink sockets.
    Netlink,
    /// `AF_PACKET` — raw packet sockets.
    Packet,
    /// Any other recognized family the parser does not model. Carries
    /// the wire tag for diagnostic display.
    Other(&'static str),
}

impl AddressFamily {
    pub(crate) fn from_wire_tag(tag: &str) -> Result<Self, Error> {
        match tag {
            "unix" => Ok(Self::Unix),
            "inet" => Ok(Self::Inet),
            "inet6" => Ok(Self::Inet6),
            "netlink" => Ok(Self::Netlink),
            "packet" => Ok(Self::Packet),
            other => Err(Error::AddressFamilyUnknown(other.to_owned())),
        }
    }
}

/// Event outcome observed for a single event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation returned an error.
    Error,
    /// The operation was interrupted (e.g. by a signal).
    Interrupted,
    /// Any other recognized outcome the parser does not model.
    Unknown,
}

impl EventOutcome {
    pub(crate) fn from_wire_tag(tag: &str) -> Result<Self, Error> {
        match tag {
            "success" => Ok(Self::Success),
            "error" => Ok(Self::Error),
            "interrupted" => Ok(Self::Interrupted),
            "unknown" => Ok(Self::Unknown),
            other => Err(Error::EventOutcomeUnknown(other.to_owned())),
        }
    }
}

/// Quality of observation coverage for the fixture. The wire tags are
/// an explicitly closed set; unknown tags fail at the boundary with
/// [`Error::CoverageTagUnknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CoverageQuality {
    /// Observation window is complete.
    Complete,
    /// Observation window is partial; non-root, dropped events, or
    /// otherwise incomplete.
    Degraded,
    /// Coverage cannot be determined.
    Unknown,
}

impl CoverageQuality {
    pub(crate) fn from_wire_tag(tag: &str) -> Result<Self, Error> {
        match tag {
            "complete" => Ok(Self::Complete),
            "degraded" => Ok(Self::Degraded),
            "unknown" => Ok(Self::Unknown),
            other => Err(Error::CoverageTagUnknown(other.to_owned())),
        }
    }

    /// The visibility-to-coverage transformation: what a
    /// [`Capability`] classification alone can say about coverage.
    ///
    /// Deliberately incapable of producing
    /// [`CoverageQuality::Complete`]: completeness can only be
    /// carried by the fixture wire envelope's `coverage` tag and
    /// composed with visibility via [`crate::combine_visibility`].
    /// Root yields [`CoverageQuality::Unknown`]; non-root and
    /// unknown visibility degrade to [`CoverageQuality::Degraded`].
    #[must_use]
    pub const fn from_capability(capability: Capability) -> Self {
        match capability {
            Capability::ExpectedRoot => Self::Unknown,
            Capability::DegradedNonRoot | Capability::Unknown => Self::Degraded,
        }
    }
}

/// A parsed fixture envelope, version v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    pub(crate) schema_version: SchemaVersion,
    pub(crate) id: String,
    pub(crate) first_timestamp: FixtureTimestamp,
    pub(crate) last_timestamp: FixtureTimestamp,
    pub(crate) coverage: CoverageQuality,
    pub(crate) seen_events: u32,
    pub(crate) dropped_events: u32,
    pub(crate) events: Vec<ObservedEvent>,
}

impl Fixture {
    /// Schema version of the envelope.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Caller-supplied fixture identifier (opaque).
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.id
    }

    /// Unix-epoch-millisecond timestamp of the first event in the
    /// declared window.
    #[must_use]
    pub const fn first_timestamp_unix_ms(&self) -> i64 {
        self.first_timestamp.unix_ms()
    }

    /// Unix-epoch-millisecond timestamp of the last event in the
    /// declared window.
    #[must_use]
    pub const fn last_timestamp_unix_ms(&self) -> i64 {
        self.last_timestamp.unix_ms()
    }

    /// Coverage quality carried on the envelope.
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.coverage
    }

    /// Number of events the observer actually captured in the
    /// declared window. The boundary guarantees
    /// `seen_events() == events().len()`.
    #[must_use]
    pub const fn seen_events(&self) -> u32 {
        self.seen_events
    }

    /// Number of events the observer reports were dropped.
    /// The boundary guarantees `dropped_events() <= seen_events()`.
    #[must_use]
    pub const fn dropped_events(&self) -> u32 {
        self.dropped_events
    }

    /// Events carried on the envelope, in wire order.
    #[must_use]
    pub fn events(&self) -> &[ObservedEvent] {
        &self.events
    }
}

/// Parse a v1 fixture envelope from raw wire bytes.
///
/// # Errors
/// See [`Error`] for the typed failure discriminants.
pub fn parse_fixture_v1(bytes: &[u8]) -> Result<Fixture, Error> {
    let wire: FixtureWireV1 = match serde_json::from_slice(bytes) {
        Ok(w) => w,
        Err(e) => return Err(map_serde_error(&e)),
    };
    let schema_version = SchemaVersion::new_fixture(wire.raw_schema_version)?;
    check_fixture_window(wire.first_timestamp_unix_ms, wire.last_timestamp_unix_ms)?;
    if wire.dropped_events > wire.seen_events {
        return Err(Error::EventLossInconsistent {
            seen: wire.seen_events,
            dropped: wire.dropped_events,
        });
    }
    if wire.events.len() != wire.seen_events as usize {
        return Err(Error::EventCountMismatch {
            declared: wire.seen_events,
            actual: u32::try_from(wire.events.len()).unwrap_or(u32::MAX),
        });
    }
    let coverage = CoverageQuality::from_wire_tag(&wire.coverage)?;
    let mut events: Vec<ObservedEvent> = Vec::with_capacity(wire.events.len());
    for (index, raw) in (0_u32..).zip(wire.events) {
        if raw.event_id.is_empty() {
            return Err(Error::EventIdEmpty { index });
        }
        events.push(ObservedEvent::new(
            SourceId::parse(&raw.source_id)?,
            raw.event_id,
            FixtureTimestamp::from_raw_checked(raw.timestamp_unix_ms),
            AddressFamily::from_wire_tag(&raw.address_family)?,
            EventOutcome::from_wire_tag(&raw.outcome)?,
            raw.args,
        ));
    }

    check_unique_event_ids(&events)?;

    Ok(Fixture {
        schema_version,
        id: wire.fixture_id,
        first_timestamp: FixtureTimestamp::from_raw_checked(wire.first_timestamp_unix_ms),
        last_timestamp: FixtureTimestamp::from_raw_checked(wire.last_timestamp_unix_ms),
        coverage,
        seen_events: wire.seen_events,
        dropped_events: wire.dropped_events,
        events,
    })
}
