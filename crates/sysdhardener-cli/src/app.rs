//! Application logic for the `sysdhardener` command surface.
//!
//! The seam is the single place that:
//! 1. reads the fixture bytes from disk and maps a filesystem
//!    failure to the typed `Error::Io` discriminant;
//! 2. runs the deterministic analysis pipeline exactly once
//!    through [`sysdhardener_core::run_analysis`];
//! 3. builds every selected `OutputSink` from the same
//!    `OutputSummary` (so the recommendation logic is not
//!    re-run per sink);
//! 4. drives every selected sink through
//!    [`sysdhardener_core::attempt_all_sinks`] exactly once and
//!    folds the typed `SinkWriteReport` into a
//!    [`ProcessOutcome`].
//!
//! Each error category maps to exactly one exit code at the
//! binary boundary (clap owns 2, the library owns 0/3/4/5). The
//! library has no notion of a process exit; the binary is the
//! only place that calls `ExitCode::from(u8)`.

// `pub(crate)` items inside a private module trip
// `redundant_pub_crate`; the explicit marker is intentional for the
// sibling-module contract (`bpf_observe.rs` reuses the analysis-error
// classification and the sink driver).
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) markers document the sibling-module contract"
)]

use std::path::Path;
use std::process::{Command, ExitCode};

use sysdhardener_core::AnalysisInput;
use sysdhardener_core::CapabilityProbe;
use sysdhardener_core::CompatibilityRecord;
use sysdhardener_core::Fixture;
use sysdhardener_core::OutputSink;
use sysdhardener_core::OutputSummary;
use sysdhardener_core::ProcStatusCapabilityProbe;
use sysdhardener_core::ProcessOutcome;
use sysdhardener_core::RestrictAddressFamilies;
use sysdhardener_core::SystemdVersion;
use sysdhardener_core::attempt_all_sinks;
use sysdhardener_core::exit_code_to_u8;
use sysdhardener_core::run_analysis_from_fixture;
use sysdhardener_core::usage_exit_code;
use sysdhardener_observer::{observe_command, observe_pid_with_duration};

use crate::cli::AnalyzeFixtureArgs;
use crate::cli::AttachArgs;
use crate::cli::ObserveArgs;
use crate::outcome_map::render_outcome;
use crate::sinks_select::SinkSelection;
use crate::sinks_select::build_sinks;

/// Run one `analyze-fixture` invocation and return the typed
/// `ProcessOutcome`. The function performs no process-exit and
/// no `tracing-subscriber` installation; the caller (`main.rs`)
/// owns the boundary.
pub fn run_analyze_fixture(args: &AnalyzeFixtureArgs) -> ProcessOutcome {
    let fixture_bytes = match load_fixture_bytes(&args.fixture) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };

    let visibility = ProcStatusCapabilityProbe.visibility();
    let compatibility = RestrictAddressFamilies::record();
    let analysis_input = AnalysisInput {
        fixture_bytes: &fixture_bytes,
        visibility,
        compatibility: &compatibility,
        raw_event_log_limit: args.max_trace_events,
    };

    let summary = match sysdhardener_core::run_analysis(&analysis_input) {
        Ok(summary) => summary,
        Err(error) => {
            // The first failing phase carries the typed
            // discriminant:
            //   parse / aggregate / recommend -> InvalidInput
            //   project / serialize -> ProcessingFailed
            //
            // `run_analysis` already logged the phase at ERROR
            // and returned the typed error; the binary maps
            // the error to exit 3 or 4.
            return classify_analysis_error(error);
        }
    };

    finalize_summary(&summary, &SinkSelection::from_analyze(args))
}

/// Run one `observe` invocation: spawn the given command under the
/// ptrace observer, capture its address-family syscalls, run them
/// through the analysis engine, and write the selected sinks.
pub fn run_observe(args: &ObserveArgs) -> ProcessOutcome {
    // clap enforces `required = true, num_args = 1..`, so the first
    // element always exists; the guard keeps the lint clean.
    let Some((program, rest)) = args.command.split_first() else {
        return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
            context: "observe requires a COMMAND argument".to_owned(),
        });
    };
    let mut command = Command::new(program);
    command.args(rest);

    let events = match observe_command(&mut command) {
        Ok(events) => events,
        Err(error) => {
            return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
                context: format!("observer failed: {error}"),
            });
        }
    };
    tracing::info!(
        target: "sysdhardener.cli",
        captured_events = events.len(),
        "live observation complete"
    );

    let fixture = sysdhardener_core::Fixture::from_events(events);
    let visibility = ProcStatusCapabilityProbe.visibility();
    let compatibility = RestrictAddressFamilies::record();
    // Resolve the host systemd version first so the analysis can gate
    // each finding's host_supported flag.
    // Probe is best-effort; `None` keeps every directive (conservative).
    let host_version = sysdhardener_core::probe_host_systemd_version();
    if let Some(host) = host_version {
        tracing::info!(
            target: "sysdhardener.cli",
            host_systemd = host.major,
            "host systemd version resolved; gating directives"
        );
    }
    let summary = match analyze_observed_fixture(
        &fixture,
        visibility,
        &compatibility,
        args.max_trace_events,
        host_version,
        sysdhardener_observer::KNOWN_UNDELIVERED_SYSCALLS,
    ) {
        Ok(summary) => summary,
        Err(error) => return classify_analysis_error(error),
    };

    finalize_summary(&summary, &SinkSelection::from_observe(args))
}

/// Run one `attach` invocation: attach to an already-running process,
/// capture its whole tree's syscalls, run them through the engine,
/// and write the selected sinks. This is the independent-observer
/// interposition — the target is not spawned by this tool.
pub fn run_attach(args: &AttachArgs) -> ProcessOutcome {
    let Ok(pid) = i32::try_from(args.pid) else {
        return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
            context: "pid does not fit in pid_t".to_owned(),
        });
    };

    let events = match observe_pid_with_duration(pid, args.duration_ms) {
        Ok(events) => events,
        Err(error) => {
            return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
                context: format!("attach failed: {error}"),
            });
        }
    };
    tracing::info!(
        target: "sysdhardener.cli",
        attached_pid = pid,
        captured_events = events.len(),
        "independent observation complete"
    );

    let fixture = sysdhardener_core::Fixture::from_events(events);
    let visibility = ProcStatusCapabilityProbe.visibility();
    let compatibility = RestrictAddressFamilies::record();
    let host_version = sysdhardener_core::probe_host_systemd_version();
    if let Some(host) = host_version {
        tracing::info!(
            target: "sysdhardener.cli",
            host_systemd = host.major,
            "host systemd version resolved; gating directives"
        );
    }
    let summary = match analyze_observed_fixture(
        &fixture,
        visibility,
        &compatibility,
        args.max_trace_events,
        host_version,
        sysdhardener_observer::KNOWN_UNDELIVERED_SYSCALLS,
    ) {
        Ok(summary) => summary,
        Err(error) => return classify_analysis_error(error),
    };

    finalize_summary(&summary, &SinkSelection::from_attach(args))
}

/// Run the shared analysis and compatibility-warning path for live evidence.
/// The caller supplies the observer-specific gap list; ptrace supplies its
/// known undelivered syscalls while eBPF supplies an empty list.
pub(crate) fn analyze_observed_fixture(
    fixture: &Fixture,
    visibility: sysdhardener_core::Capability,
    compatibility: &CompatibilityRecord,
    raw_event_log_limit: usize,
    host_version: Option<SystemdVersion>,
    known_gaps: &[&'static str],
) -> Result<OutputSummary, sysdhardener_core::Error> {
    let summary = run_analysis_from_fixture(
        fixture,
        visibility,
        compatibility,
        raw_event_log_limit,
        host_version,
        known_gaps,
    )?;

    for finding in &summary.findings {
        if !finding.host_supported() {
            tracing::warn!(
                target: "sysdhardener.cli",
                directive = finding.directive(),
                host_systemd = host_version.map_or(0, |v| v.major),
                "directive skipped: host systemd is older than the directive's introduced-in version"
            );
        }
    }

    Ok(summary)
}

/// Create the selected output directory, build every sink from one summary,
/// and drive each sink exactly once.
pub(crate) fn finalize_summary(
    summary: &OutputSummary,
    selection: &SinkSelection<'_>,
) -> ProcessOutcome {
    if let Err(error) = std::fs::create_dir_all(selection.output_dir) {
        return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::OutputDirUnavailable {
            context: format!("{error}"),
        });
    }

    let sinks = build_sinks(selection, summary);
    attempt_sinks(&sinks)
}

/// Read the fixture bytes from disk. The typed `Error::Io` is
/// constructed with a stable, redacted context string (no
/// absolute host paths leak into the discriminant) and returned
/// to the caller as `ProcessOutcome::InvalidInput`.
fn load_fixture_bytes(path: &Path) -> Result<Vec<u8>, ProcessOutcome> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(io_error) => Err(ProcessOutcome::InvalidInput(sysdhardener_core::Error::Io {
            context: format!("failed to read fixture file: {io_error}"),
        })),
    }
}

/// Map an analysis-phase error to the typed `ProcessOutcome`.
/// `run_analysis` and `build_sinks` both return `Error`; the
/// typed discriminant decides whether the failure is "invalid
/// input" (parse/serialize) or "processing failed" (everything
/// else). This mapping is maintained in one place, not scattered.
///
/// `Error` is `#[non_exhaustive]`; the wildcard arm is
/// required and maps to `ProcessingFailed` (exit 4) so a
/// future variant added by the library is never silently
/// downgraded to "invalid input".
pub(crate) const fn classify_analysis_error(error: sysdhardener_core::Error) -> ProcessOutcome {
    use sysdhardener_core::Error as E;
    match error {
        // Schema/JSON/fixture shape rejections are all input
        // boundary failures, exit 3.
        E::SchemaUnknown { .. }
        | E::SourceIdMalformed(_)
        | E::TimestampReversed { .. }
        | E::AddressFamilyUnknown(_)
        | E::EventOutcomeUnknown(_)
        | E::CoverageTagUnknown(_)
        | E::FixtureFieldMissing { .. }
        | E::EventCountMismatch { .. }
        | E::EventLossInconsistent { .. }
        | E::EventIdDuplicate { .. }
        | E::EventIdEmpty { .. }
        | E::Io { .. }
        | E::JsonSyntax { .. }
        | E::JsonShape(_) => ProcessOutcome::InvalidInput(error),
        E::ReportSerialize(_)
        | E::ReportFieldMissing { .. }
        | E::OutputDirUnavailable { .. }
        | E::CompatibilityUnknownSource(_)
        | E::UnlinkedConciseSetting { .. }
        | E::SinkWriteFailed { .. }
        | _ => ProcessOutcome::ProcessingFailed(error),
    }
}

/// Drive every selected sink through
/// [`sysdhardener_core::attempt_all_sinks`], then fold the
/// `SinkWriteReport` into a typed `ProcessOutcome`. The success
/// surface is preserved on partial failure; the function never
/// re-runs a sink and never deletes a successful output.
pub(crate) fn attempt_sinks(sinks: &[Box<dyn OutputSink>]) -> ProcessOutcome {
    match attempt_all_sinks(sinks) {
        Ok(report) => {
            if report.any_failed() {
                ProcessOutcome::SinkWritePartialFailure(report)
            } else {
                ProcessOutcome::Success
            }
        }
        // `attempt_all_sinks` is infallible by contract; the
        // `Err` arm documents the invariant.
        Err(error) => ProcessOutcome::ProcessingFailed(error),
    }
}

/// The binary boundary: convert a `ProcessOutcome` into the
/// numeric exit code, write the stderr diagnostics, and return
/// the `ExitCode`. The function is the only place that calls
/// `ExitCode::from(u8)`.
#[must_use]
pub fn exit_code_for_outcome(outcome: &ProcessOutcome) -> ExitCode {
    ExitCode::from(exit_code_to_u8(outcome))
}

/// The usage-exit boundary. Used by `main.rs` when the binary
/// validates the parsed args and finds a business-level
/// configuration error (e.g. no file sink selected). clap owns
/// the parse-error 2; this function exposes the same value so
/// the binary has one call site for the usage constant.
///
/// `ExitCode::from(u8)` is not `const` in stable Rust, so the
/// function is not `const` either; the call site is still a
/// single expression, so the boundary stays in one place.
#[must_use]
pub fn exit_code_for_usage_error() -> ExitCode {
    ExitCode::from(usage_exit_code())
}

/// Write the typed stderr diagnostics for the outcome. Each line
/// is a stable, machine-greppable string (the E2E tests assert
/// on the typed discriminants, not on prose).
pub fn write_stderr_diagnostics(outcome: &ProcessOutcome) {
    use std::io::Write as _;
    let stderr = std::io::stderr();
    let mut handle = stderr.lock();
    for line in render_outcome(outcome) {
        let _ = writeln!(handle, "{}", line.0);
    }
}
