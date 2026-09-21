//! Outcome mapping: convert the typed `ProcessOutcome` (and the
//! sink-only success path) into a stable binary-level decision
//! plus the stderr diagnostics the user reads.
//!
//! The binary is the only place that calls `ExitCode::from(u8)`.
//! The mapping has two halves:
//! 1. the typed `Error` carried by `InvalidInput` /
//!    `ProcessingFailed` is rendered as a single human-readable
//!    line on stderr so the user knows *what* failed; the
//!    underlying discriminant (e.g. `SchemaUnknown`,
//!    `JsonSyntax`, `UnlinkedConciseSetting`, `Io`) is included
//!    in the line so the message is machine-greppable without
//!    parsing prose;
//! 2. the typed `SinkWriteReport` carried by
//!    `SinkWritePartialFailure` is summarized as one line per
//!    failure (sink name + destination path + categorized
//!    failure kind) and one line per success (sink name +
//!    destination path), preserving the "all selected sinks are
//!    attempted, successes are kept" invariant.
//!
//! The summary deliberately uses short, stable prefixes so the
//! assertions in the E2E test can match on the typed names
//! (`detailed`, `concise`, `json`) without depending on
//! punctuation or wording.

use sysdhardener_core::ProcessOutcome;
use sysdhardener_core::SinkWriteReport;

/// One line of stderr diagnostics (without trailing newline). The
/// caller writes it to stderr with `writeln!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StderrLine(pub String);

/// Render the typed [`ProcessOutcome`] as a vector of stderr
/// diagnostics. The vector is empty for `Success` (the
/// recommendation lives only in the output files;
/// success is silent on stderr at INFO). For
/// `SinkWritePartialFailure`, every failure and every success
/// gets its own line so the user can see which sinks were
/// attempted, which succeeded, and which failed.
#[must_use]
pub fn render_outcome(outcome: &ProcessOutcome) -> Vec<StderrLine> {
    match outcome {
        ProcessOutcome::Success => Vec::new(),
        ProcessOutcome::InvalidInput(error) => {
            vec![StderrLine(format!("error: invalid input: {error}"))]
        }
        ProcessOutcome::ProcessingFailed(error) => {
            vec![StderrLine(format!("error: processing failed: {error}"))]
        }
        ProcessOutcome::SinkWritePartialFailure(report) => render_sink_report(report),
        // `ProcessOutcome` is `#[non_exhaustive]`; a future
        // variant added by the library must be rendered as
        // a generic processing-failure line so the user still
        // sees the failure mode.
        _ => vec![StderrLine(
            "error: processing failed: <unknown variant>".to_owned(),
        )],
    }
}

/// Render a typed [`SinkWriteReport`] as a list of stderr
/// diagnostics. The user must be able to see
/// every attempted sink, so the function lists both successes and
/// failures with a single-line `writeln!`-ready form.
fn render_sink_report(report: &SinkWriteReport) -> Vec<StderrLine> {
    let mut lines: Vec<StderrLine> = Vec::new();
    for success in report.successes() {
        lines.push(StderrLine(format!("sink: ok {success}")));
    }
    for failure in report.failures() {
        lines.push(StderrLine(format!("sink: failed {failure}")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_renders_no_stderr_lines() {
        let lines = render_outcome(&ProcessOutcome::Success);
        assert!(lines.is_empty(), "Success must be silent on stderr");
    }

    #[test]
    fn invalid_input_renders_single_stderr_line_with_discriminant() {
        let outcome = ProcessOutcome::InvalidInput(sysdhardener_core::Error::SchemaUnknown {
            found: 99,
            supported: sysdhardener_core::SUPPORTED_FIXTURE_SCHEMA,
        });
        let lines = render_outcome(&outcome);
        assert_eq!(lines.len(), 1);
        let first = lines.first().expect("lines has one entry");
        assert!(first.0.contains("invalid input"));
        assert!(first.0.contains("99"));
    }

    #[test]
    fn processing_failed_renders_single_stderr_line() {
        let outcome =
            ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::UnlinkedConciseSetting {
                recommended: Vec::new(),
                finding_index: Some(0),
            });
        let lines = render_outcome(&outcome);
        assert_eq!(lines.len(), 1);
        let first = lines.first().expect("lines has one entry");
        assert!(first.0.contains("processing failed"));
    }

    #[test]
    fn report_field_missing_is_processing_failed_not_invalid_input() {
        let outcome =
            crate::app::classify_analysis_error(sysdhardener_core::Error::ReportFieldMissing {
                field: "test",
            });
        assert!(
            matches!(outcome, ProcessOutcome::ProcessingFailed(_)),
            "ReportFieldMissing should map to ProcessingFailed (exit 4)"
        );
    }
}
