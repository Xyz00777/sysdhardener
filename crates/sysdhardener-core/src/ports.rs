//! Public ports (trait interfaces) and the visibility value object.
//!
//! The traits are the only observation-source, output-sink, and
//! capability-probe surfaces in the crate. The concrete
//! implementations live in sibling modules: the fixture-backed
//! [`EventSource`] implementation is [`crate::FixtureEventSource`],
//! the three sink adapters are [`crate::DetailedFileSink`],
//! [`crate::ConciseFileSink`], and [`crate::JsonFileSink`], and the
//! real Linux capability probe is
//! [`crate::ProcStatusCapabilityProbe`]. The traits contain no
//! behavior — they are contracts, not implementations.

use crate::error::Error;
use crate::fixture::CoverageQuality;
use crate::observed_event::ObservedEvent;
use std::path::PathBuf;

/// A source of `ObservedEvent` values. The single concrete
/// implementation is [`crate::FixtureEventSource`] (fixture-backed);
/// no live observer exists in this deliverable.
///
/// The trait returns a `Vec<ObservedEvent>` rather than a streaming
/// iterator so every consumer in the deterministic slice sees the same
/// in-memory shape; streaming is not part of the first deliverable.
pub trait EventSource {
    /// Return all observed events in deterministic wire order.
    ///
    /// # Errors
    /// Returns [`Error`] when the source cannot produce events
    /// (fixture unreadable, schema mismatch, etc.).
    fn collect(&self) -> Result<Vec<ObservedEvent>, Error>;
}

/// A sink that writes a completed report artifact.
///
/// Sinks return their own typed success or failure; the caller
/// attempts every selected sink exactly once and preserves
/// successes on partial failure. The sink is constructed with the
/// typed data it owns (a `DetailedProjection`, a `ConciseProjection`,
/// or a `Report`); on `write` it serializes and writes to its
/// destination.
pub trait OutputSink {
    /// Serialize and write the sink's pre-loaded data to its
    /// destination. The caller drives this exactly once
    /// per selected sink.
    ///
    /// # Errors
    /// Returns [`Error::SinkWriteFailed`] when the create / write /
    /// flush sequence fails. The discriminant carries the sink's
    /// stable name, the destination path, and the categorized
    /// create/write/flush failure; the consumer matches on the
    /// discriminant rather than parsing prose.
    fn write(&self) -> Result<(), Error>;

    /// A stable, short name identifying this sink for diagnostics
    /// (e.g. `"detailed"`, `"concise"`, `"json"`).
    fn name(&self) -> &'static str;

    /// The destination path the sink writes to. The aggregator
    /// needs the path on both the success and the
    /// failure branches; the file sinks own the path on the
    /// success branch, and the [`Error::SinkWriteFailed`]
    /// discriminant carries it on the failure branch. The trait
    /// surface exposes it so the success record can be honest
    /// about where the bytes landed.
    fn destination(&self) -> PathBuf;
}

/// Visibility classification produced by a [`CapabilityProbe`]. The
/// typed variants map to three classifications
/// (`ExpectedRoot`, `DegradedNonRoot`, `Unknown`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// The probe determined the process is running as the expected
    /// root identity. Root alone does not imply complete observation.
    ExpectedRoot,
    /// The probe determined the process is not running as the expected
    /// root identity; visibility is degraded.
    DegradedNonRoot,
    /// The probe could not determine the visibility.
    Unknown,
}

/// Visibility assessment for the current process. The real Linux
/// `/proc/self/status` reader is [`crate::ProcStatusCapabilityProbe`];
/// the trait is the contract every consumer in the slice depends on.
pub trait CapabilityProbe {
    /// The typed visibility classification.
    fn visibility(&self) -> Capability;
}

/// Compose process visibility with evidence coverage into the
/// effective coverage of a result.
///
/// The composition is total and exhaustive over both values:
/// - [`Capability::ExpectedRoot`] preserves the evidence coverage
///   unchanged — root never upgrades, never downgrades, and never
///   fabricates completeness;
/// - [`Capability::DegradedNonRoot`] and [`Capability::Unknown`]
///   always degrade the result to [`CoverageQuality::Degraded`],
///   even when the evidence claimed complete.
///
/// `CoverageQuality::Complete` is therefore reachable only when the
/// fixture wire envelope carried it *and* the capability is
/// [`Capability::ExpectedRoot`]; a UID classification alone can
/// never produce it (see [`CoverageQuality::from_capability`]).
#[must_use]
pub const fn combine_visibility(
    capability: Capability,
    coverage: CoverageQuality,
) -> CoverageQuality {
    match (capability, coverage) {
        (Capability::ExpectedRoot, coverage) => coverage,
        (Capability::DegradedNonRoot | Capability::Unknown, _) => CoverageQuality::Degraded,
    }
}

/// Compile-time proof that a [`Capability`] classification alone can
/// never produce [`CoverageQuality::Complete`]. Evaluated at compile
/// time; if [`CoverageQuality::from_capability`] ever maps any
/// capability to `Complete`, this crate fails to build.
#[allow(
    clippy::panic,
    reason = "compile-time invariant guard: capability alone must never imply complete coverage"
)]
const _: () = {
    match CoverageQuality::from_capability(Capability::ExpectedRoot) {
        CoverageQuality::Complete => panic!("ExpectedRoot must never imply complete coverage"),
        CoverageQuality::Degraded | CoverageQuality::Unknown => {}
    }
    match CoverageQuality::from_capability(Capability::DegradedNonRoot) {
        CoverageQuality::Complete => panic!("DegradedNonRoot must never imply complete coverage"),
        CoverageQuality::Degraded | CoverageQuality::Unknown => {}
    }
    match CoverageQuality::from_capability(Capability::Unknown) {
        CoverageQuality::Complete => {
            panic!("Unknown capability must never imply complete coverage")
        }
        CoverageQuality::Degraded | CoverageQuality::Unknown => {}
    }
};
