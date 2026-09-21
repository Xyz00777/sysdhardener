//! Typed process outcome and exit-code mapping.
//!
//! A typed application outcome that the binary
//! boundary converts to numeric exit codes. The library carries
//! the typed values and the conversion function; the binary is
//! the only place that calls the `ExitCode` boundary constructor.
//!
//! Mapping (locked by the integration test):
//! - [`ProcessOutcome::Success`] -> 0
//! - [`ProcessOutcome::InvalidInput`] -> 3 (input/fixture/schema)
//! - [`ProcessOutcome::ProcessingFailed`] -> 4 (analysis/projection)
//! - [`ProcessOutcome::SinkWritePartialFailure`] -> 5 (any selected
//!   sink failed after all attempts)
//!
//! The "no selected file sink" case is a clap usage error and is
//! mapped to exit code 2 by the binary, not the library. The
//! library exposes [`usage_exit_code`] so the boundary stays the
//! single point of truth for usage-exit semantics.
//!
//! This module is pure: no I/O, no wall clock, no `tracing`, and
//! no process-terminate call. Every helper is `const` where
//! possible so the boundary conversion adds no runtime cost.

use crate::error::Error;
use crate::sink_outcome::SinkWriteReport;

/// Typed application outcome.
///
/// Each variant carries the data the binary boundary needs to
/// convert the outcome to a numeric exit code without re-deriving
/// the cause from prose. The enum is `#[non_exhaustive]` so a
/// future variant (e.g. a new analysis phase) can be added
/// without breaking the binary's match.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProcessOutcome {
    /// All selected sinks wrote successfully, and the underlying
    /// analysis surfaced a recommendation. The recommendation may
    /// still carry degraded-visibility or unknown-compatibility
    /// labels; those labels do not change the exit code because
    /// the run completes successfully.
    Success,

    /// The input boundary rejected the call: an unknown fixture
    /// schema, a malformed JSON, a missing required field, an
    /// unreadable fixture file, or any other input/fixture
    /// failure. Carries the typed [`Error`] discriminant.
    InvalidInput(Error),

    /// The input parsed, the evidence aggregated, and the
    /// recommendation derived without a sink involvement — but
    /// one of the analysis phases returned a typed error
    /// (coverage, recommendation, projection, serialization).
    /// Carries the typed [`Error`] discriminant.
    ProcessingFailed(Error),

    /// At least one selected sink failed after every selected
    /// sink was attempted exactly once. Successes are preserved
    /// in the carried [`SinkWriteReport`]; the binary boundary
    /// uses the failures to drive diagnostics and exits 5.
    SinkWritePartialFailure(SinkWriteReport),
}

impl ProcessOutcome {
    /// `true` when the outcome is a complete success (all
    /// selected sinks wrote and the analysis produced a
    /// recommendation).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    /// `true` when the outcome carries at least one selected
    /// sink failure.
    #[must_use]
    pub const fn is_sink_partial_failure(&self) -> bool {
        matches!(self, Self::SinkWritePartialFailure(_))
    }
}

/// Map a typed [`ProcessOutcome`] to the numeric exit code the
/// binary boundary hands to `ExitCode::from(u8)`.
///
/// The mapping is total and exhaustive over the four
/// non-exhaustive variants. A future variant will require a new
/// arm here, which the compiler enforces as long as the caller
/// is in this crate and `#[non_exhaustive]` is respected.
///
/// The exit codes:
/// - 0 — all selected sinks succeeded
/// - 3 — input/fixture/schema rejection
/// - 4 — analysis/processing/serialization failure
/// - 5 — one or more selected sinks failed after every selected
///   sink was attempted
#[must_use]
pub const fn exit_code_to_u8(outcome: &ProcessOutcome) -> u8 {
    match outcome {
        ProcessOutcome::Success => 0,
        ProcessOutcome::InvalidInput(_) => 3,
        ProcessOutcome::ProcessingFailed(_) => 4,
        ProcessOutcome::SinkWritePartialFailure(_) => 5,
    }
}

/// The exit code the binary boundary returns when clap rejects
/// the invocation.
///
/// Covers unknown flags, missing positional arguments, and the
/// "no selected file sink" case assigned to usage
/// semantics. The library exposes the value as a single
/// function so the binary has one call site to learn the
/// constant from.
#[must_use]
pub const fn usage_exit_code() -> u8 {
    2
}
