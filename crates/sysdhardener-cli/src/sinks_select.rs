//! Sink selection: which `OutputSink` adapters to run, and where
//! each one's bytes go.
//!
//! The selection is a typed value produced from the parsed CLI:
//! - the detailed sink writes to `<output-dir>/findings.txt`
//!   when `--no-detailed` is not set;
//! - the concise sink writes to `<output-dir>/hardening.conf`
//!   when `--no-concise` is not set;
//! - the JSON sink writes to the caller-supplied `--json <PATH>`
//!   when present.
//!
//! The function returns the typed `Box<dyn OutputSink>` list in
//! caller order. The recommendation logic is run **once** in
//! [`crate::app::run_analyze_fixture`] and the `OutputSummary` is
//! fed to every selected sink at construction time; the sinks own
//! their pre-serialized bytes so the write step is a single
//! `File::create` + `write_all` per sink. This is the
//! "all sinks from one `OutputSummary`/finding and report-v1
//! data without rerunning recommendation logic" invariant.

use sysdhardener_core::ConciseFileSink;
use sysdhardener_core::DetailedFileSink;
use sysdhardener_core::JsonFileSink;
use sysdhardener_core::OutputSink;
use sysdhardener_core::OutputSummary;

use crate::cli::AnalyzeFixtureArgs;
use crate::cli::AttachArgs;
use crate::cli::ObserveArgs;

/// The detailed output filename the binary owns inside `--output-dir`.
pub const DETAILED_FILENAME: &str = "findings.txt";

/// The concise output filename the binary owns inside `--output-dir`.
pub const CONCISE_FILENAME: &str = "hardening.conf";

/// The single message printed when the caller selected no file sink.
pub const USAGE_NO_SINK: &str = "at least one file sink must be selected: omit --no-detailed, omit --no-concise, or supply --json <PATH>";

/// Printed when `--json <PATH>` equals the selected detailed sink destination.
pub const USAGE_JSON_COLLIDES_WITH_DETAILED: &str = "--json <PATH> collides with the detailed output path (<output-dir>/findings.txt); choose a different --json path or pass --no-detailed";

/// Printed when `--json <PATH>` equals the selected concise sink destination.
pub const USAGE_JSON_COLLIDES_WITH_CONCISE: &str = "--json <PATH> collides with the concise output path (<output-dir>/hardening.conf); choose a different --json path";

/// The caller-ordered list of `OutputSink` adapters selected by the
/// CLI. The recommendation logic runs once in
/// [`crate::app::run_analyze_fixture`]; every sink is constructed
/// with pre-serialized bytes from the same `OutputSummary`.
pub type BuiltSinks = Vec<Box<dyn OutputSink>>;

/// The sink-selection surface shared by `analyze-fixture` and
/// `observe`: which default sinks are dropped, where the JSON
/// sink (if any) writes, and whether the detailed view carries
/// pid attribution.
pub struct SinkSelection<'a> {
    /// The output directory for the default file sinks.
    pub output_dir: &'a std::path::Path,
    /// Whether the detailed sink is deselected.
    pub no_detailed: bool,
    /// Whether the concise sink is deselected.
    pub no_concise: bool,
    /// Optional JSON sink destination.
    pub json: Option<&'a std::path::Path>,
    /// Whether the detailed file lists the observed pids
    /// (live-observer mode).
    pub show_pids: bool,
}

impl<'a> SinkSelection<'a> {
    /// Build the selection from `analyze-fixture` args.
    #[must_use]
    pub fn from_analyze(args: &'a AnalyzeFixtureArgs) -> Self {
        Self {
            output_dir: &args.output_dir,
            no_detailed: args.no_detailed,
            no_concise: args.no_concise,
            json: args.json.as_deref(),
            show_pids: false,
        }
    }

    /// Build the selection from `attach` args.
    #[must_use]
    pub fn from_attach(args: &'a AttachArgs) -> Self {
        Self {
            output_dir: &args.output_dir,
            no_detailed: args.no_detailed,
            no_concise: args.no_concise,
            json: args.json.as_deref(),
            show_pids: args.show_pids,
        }
    }

    /// Build the selection from `observe` args.
    #[must_use]
    pub fn from_observe(args: &'a ObserveArgs) -> Self {
        Self {
            output_dir: &args.output_dir,
            no_detailed: args.no_detailed,
            no_concise: args.no_concise,
            json: args.json.as_deref(),
            show_pids: args.show_pids,
        }
    }

    /// Build the selection from `bpf-observe` args.
    #[cfg(feature = "bpf-observe")]
    #[must_use]
    pub fn from_bpf(args: &'a crate::bpf_observe::BpfObserveArgs) -> Self {
        Self {
            output_dir: &args.output_dir,
            no_detailed: args.no_detailed,
            no_concise: args.no_concise,
            json: args.json.as_deref(),
            show_pids: args.show_pids,
        }
    }
}

/// Build the caller-ordered list of [`OutputSink`] adapters from
/// the sink selection and the typed [`OutputSummary`].
///
/// The function performs the "all sinks from one summary" mapping:
/// every sink is constructed with a pre-serialized byte buffer
/// from the same `OutputSummary` so the recommendation logic runs
/// exactly once. The order is `detailed`, `concise`, `json` (the
/// stable caller order); when a sink is not selected by
/// the CLI it is omitted.
#[must_use]
pub fn build_sinks(selection: &SinkSelection<'_>, summary: &OutputSummary) -> BuiltSinks {
    let mut sinks: Vec<Box<dyn OutputSink>> = Vec::new();
    let findings_slice: &[sysdhardener_core::Finding] = &summary.findings;

    if !selection.no_detailed {
        let path = selection.output_dir.join(DETAILED_FILENAME);
        let pids: &[i32] = if selection.show_pids {
            &summary.observed_pids
        } else {
            &[]
        };
        let sink = DetailedFileSink::new_with_pids(
            &path,
            findings_slice,
            pids,
            &summary.known_gaps,
            &summary.observed_cgroups,
        );
        sinks.push(Box::new(sink));
    }

    if !selection.no_concise {
        let path = selection.output_dir.join(CONCISE_FILENAME);
        let sink = ConciseFileSink::from_projection(&path, &summary.concise);
        sinks.push(Box::new(sink));
    }

    if let Some(json_path) = selection.json {
        // The report was already serialized once by the analysis
        // phase; the JSON sink consumes those bytes instead of
        // serializing a second time from a cloned finding.
        let sink = JsonFileSink::from_bytes(json_path, summary.report_bytes.clone());
        sinks.push(Box::new(sink));
    }

    sinks
}

/// Shared sink-selection validation for `observe` and `attach`.
#[allow(
    clippy::redundant_pub_crate,
    reason = "crate-visible for the cli module"
)]
pub(crate) fn validate_sink_selection(
    no_detailed: bool,
    no_concise: bool,
    json: Option<&std::path::Path>,
    output_dir: &std::path::Path,
) -> Result<(), String> {
    if no_detailed && no_concise && json.is_none() {
        return Err(USAGE_NO_SINK.to_owned());
    }
    if let Some(json) = json {
        if !no_detailed && lexical_equal(json, &output_dir.join(DETAILED_FILENAME)) {
            return Err(USAGE_JSON_COLLIDES_WITH_DETAILED.to_owned());
        }
        if !no_concise && lexical_equal(json, &output_dir.join(CONCISE_FILENAME)) {
            return Err(USAGE_JSON_COLLIDES_WITH_CONCISE.to_owned());
        }
    }
    Ok(())
}

/// Lexical path equality: `a/../b` == `b` after component normalization.
/// Resolves relative paths against the current working directory so leading
/// `..` components are correctly normalized and do not cause false collisions.
fn lexical_equal(a: &std::path::Path, b: &std::path::Path) -> bool {
    let cwd = std::env::current_dir().ok();
    let to_full = |p: &std::path::Path| {
        if p.is_absolute() {
            p.to_path_buf()
        } else if let Some(ref cwd) = cwd {
            cwd.join(p)
        } else {
            p.to_path_buf()
        }
    };
    sysdhardener_core::normalize_path(&to_full(a)) == sysdhardener_core::normalize_path(&to_full(b))
}
