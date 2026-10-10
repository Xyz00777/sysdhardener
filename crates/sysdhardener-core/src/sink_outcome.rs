//! Exactly-once selected-sink aggregation.
//!
//! Every selected `OutputSink` is attempted
//! exactly once, in caller order; that successes are preserved
//! with their sink name and destination path; and that every
//! failure is collected with the same data (already carried by
//! [`Error::SinkWriteFailed`]). There is no retry, no rollback, and
//! no deletion of successful outputs after another sink fails.
//!
//! This module owns the data, not the orchestration: the
//! [`attempt_all_sinks`] helper is the only function that drives
//! the per-sink [`OutputSink::write`] calls. Every other consumer
//! reads the resulting [`SinkWriteReport`] instead of calling
//! `write` itself, so the "exactly once" invariant has one call
//! site. Degraded-visibility and unknown-compatibility warnings
//! never create a sink failure: the success surface is preserved
//! when every selected sink wrote successfully.

use std::fmt;
use std::path::PathBuf;

use crate::error::Error;
use crate::ports::OutputSink;

/// One sink that succeeded during the aggregation pass.
///
/// Carries the sink's stable name and destination path so the
/// binary boundary can surface "wrote `/tmp/findings.txt` via
/// `detailed`" without re-deriving the data from prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkWriteSuccess {
    sink_name: &'static str,
    path: PathBuf,
}

impl SinkWriteSuccess {
    /// Construct a success record. The caller (the aggregator)
    /// guarantees the sink actually wrote to `path`.
    #[must_use]
    pub const fn new(sink_name: &'static str, path: PathBuf) -> Self {
        Self { sink_name, path }
    }

    /// The sink's stable name (`"detailed"`, `"concise"`, `"json"`,
    /// or another registered sink).
    #[must_use]
    pub const fn sink_name(&self) -> &'static str {
        self.sink_name
    }

    /// The destination path the sink wrote to.
    #[must_use]
    pub const fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl fmt::Display for SinkWriteSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} -> {}", self.sink_name, self.path.display())
    }
}

/// Aggregated result of attempting every selected `OutputSink`.
///
/// `successes` and `failures` are stored in caller order, never
/// sorted or coalesced. A failure always carries the
/// [`Error::SinkWriteFailed`] discriminant, which already names
/// the sink and the destination path; the aggregator does not
/// re-derive the data from prose.
#[derive(Debug, Default)]
pub struct SinkWriteReport {
    successes: Vec<SinkWriteSuccess>,
    failures: Vec<Error>,
}

impl SinkWriteReport {
    /// Build a report directly from pre-collected attempts.
    ///
    /// The success names must be unique within the success list;
    /// a duplicated name signals a caller bug, and the function
    /// refuses to construct a report that double-counts the same
    /// sink. Failures are not checked for duplicate names because
    /// a future retry path (out of this slice's scope) may
    /// legitimately record the same sink twice.
    ///
    /// # Errors
    /// Returns a synthetic [`Error::SinkWriteFailed`] if a
    /// success name is duplicated; the synthetic error names the
    /// aggregator so the binary boundary can fail loudly instead
    /// of shipping a report that mis-reports successes.
    pub fn from_attempts(
        successes: Vec<(&'static str, PathBuf)>,
        failures: Vec<Error>,
    ) -> Result<Self, Error> {
        let mut seen: Vec<&'static str> = successes.iter().map(|(name, _)| *name).collect();
        seen.sort_unstable();
        let previous = seen.len();
        seen.dedup();
        if seen.len() != previous {
            return Err(Error::SinkWriteFailed {
                sink: "<aggregator>",
                path: PathBuf::from("<synthetic: duplicate success name>"),
                kind: crate::error::SinkWriteFailure::Create {
                    io: "SinkWriteReport::from_attempts forbids duplicate success names".to_owned(),
                },
            });
        }
        let successes: Vec<SinkWriteSuccess> = successes
            .into_iter()
            .map(|(sink_name, path)| SinkWriteSuccess::new(sink_name, path))
            .collect();
        Ok(Self {
            successes,
            failures,
        })
    }

    /// All sink attempts that returned `Ok(())`, in caller order.
    #[must_use]
    pub fn successes(&self) -> &[SinkWriteSuccess] {
        &self.successes
    }

    /// All sink attempts that returned `Err(_)`, in caller order.
    /// Every entry is [`Error::SinkWriteFailed`] (or a future
    /// typed sink failure added by an [`OutputSink`] implementation
    /// outside this slice).
    #[must_use]
    pub fn failures(&self) -> &[Error] {
        &self.failures
    }

    /// `true` if at least one selected sink failed.
    #[must_use]
    pub const fn any_failed(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Number of selected sinks that failed.
    #[must_use]
    pub const fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Number of selected sinks that succeeded.
    #[must_use]
    pub const fn success_count(&self) -> usize {
        self.successes.len()
    }
}

/// Attempt every selected `OutputSink` exactly once, in caller
/// order.
///
/// The helper enforces the invariants:
///
/// - each sink is driven through [`OutputSink::write`] exactly
///   once; the helper never retries, never re-resolves, and
///   never silently skips a sink;
/// - a sink that returned `Ok(())` becomes a [`SinkWriteSuccess`]
///   carrying the sink's [`OutputSink::name`] and the path the
///   sink reports via [`OutputSink::destination`];
/// - a sink that returned `Err(_)` is appended to the failures
///   list with no transformation. The error already carries the
///   sink name and the destination path.
///
/// # Errors
/// Never returns an error: every failure is collected, not
/// raised. The returned report is `Ok(())` even when every
/// selected sink failed.
pub fn attempt_all_sinks(sinks: &[Box<dyn OutputSink>]) -> Result<SinkWriteReport, Error> {
    let mut successes: Vec<(&'static str, PathBuf)> = Vec::new();
    let mut failures: Vec<Error> = Vec::new();
    for sink in sinks {
        match sink.write() {
            Ok(()) => successes.push((sink.name(), sink.destination())),
            Err(error) => failures.push(error),
        }
    }
    // `from_attempts` enforces the duplicate-success-name invariant
    // on the production path, not just in tests.
    SinkWriteReport::from_attempts(successes, failures)
}
