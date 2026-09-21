//! Command-line argument parsing for the `sysdhardener` binary.
//!
//! The binary exposes subcommands for analyzing fixtures (`analyze-fixture`),
//! live process observation (`observe`), process tree attachment (`attach`),
//! and optional eBPF cgroup tracing (`bpf-observe`),
//! plus the inherited `--help`/`--version` flags. The
//! `analyze-fixture` surface provides:
//! - positional `<FIXTURE>` (path to a v1 fixture envelope);
//! - required `--output-dir <DIR>`;
//! - opt-in `--json <PATH>` to write the report envelope v1;
//! - `--no-detailed` / `--no-concise` to drop a default file sink;
//! - `--max-trace-events <N>` (alias `--max-raw-events`) to cap the bounded raw-event TRACE
//!   emission (0 disables);
//! - opt-in `--trace-file <PATH>` for dedicated raw event debug logging;
//! - repeated `--verbose <LEVEL>` to drive the verbosity dial
//!   through `trace|debug|info|warn|error|off` (multiple uses are
//!   accepted but the first occurrence wins, `default` included).
//!
//! Parse errors are clap's: clap returns its own usage error to
//! stderr and exits with code 2. The "no selected file sink" case
//! (selecting `--no-detailed` and `--no-concise` without supplying
//! `--json`) is a *business* usage error, not a clap error; the
//! parser still returns a value and the binary maps the
//! validation to its own message + clap's exit code 2.

// `pub(crate)` items inside a private module trip
// `redundant_pub_crate`; the explicit marker is intentional for the
// sibling-module contract (`bpf_observe.rs` reuses the verbosity
// parser).
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) markers document the sibling-module contract"
)]

use std::path::PathBuf;

use clap::Parser;

use crate::sinks_select::validate_sink_selection;
use crate::tracing_init::{Verbosity, resolve_verbosity};

/// Top-level clap entry point. The binary is `sysdhardener`; the
/// subcommand is `analyze-fixture`. Help and version are clap-owned
/// and produce the standard exit codes 0 and 2.
#[derive(Debug, Parser)]
#[command(
    name = "sysdhardener",
    about = "Provisional systemd hardening recommender.",
    long_about = "Analyzes fixture evidence or observes a real target, derives \
                  provisional systemd hardening recommendations, and writes \
                  selected output files. JSON is opt-in; lifecycle logs go to stderr.",
    version
)]
pub struct Cli {
    /// Subcommand to execute. `None` is impossible because `clap`
    /// returns its own error when the subcommand is missing.
    #[command(subcommand)]
    pub command: Commands,
}

/// Commands shipped in this deliverable.
#[derive(Debug, clap::Subcommand)]
pub enum Commands {
    /// Analyze a v1 fixture envelope and write the recommendation
    /// artifacts to `--output-dir` (and optionally `--json`).
    AnalyzeFixture(AnalyzeFixtureArgs),
    /// Observe a real process: spawn the given command under the
    /// ptrace observer, capture its address-family syscalls, run them
    /// through the analysis engine, and write the recommendation
    /// artifacts. This is the live-observer mode of the product.
    Observe(ObserveArgs),
    /// Attach to an already-running process (the independent
    /// observer interposition): the target is not spawned by this
    /// tool and keeps its systemd-managed identity. Requires the
    /// ptrace permission (same-UID or root).
    Attach(AttachArgs),
    /// Attach the eBPF observer to a target cgroup and capture
    /// socket-family evidence (feature-gated: `--features bpf-observe`).
    #[cfg(feature = "bpf-observe")]
    BpfObserve(crate::bpf_observe::BpfObserveArgs),
}
pub use crate::cli_observe::{AttachArgs, ObserveArgs};

/// The argument set for `sysdhardener analyze-fixture`. Clap
/// enforces the shape at the boundary. The parser
/// is a pure DTO: validation that is not a clap parse error
/// (e.g. "no selected file sink") lives in [`Self::validate`].
#[derive(Debug, clap::Args)]
pub struct AnalyzeFixtureArgs {
    /// Path to the v1 fixture envelope. Read from disk; rejected
    /// with exit code 3 when missing or malformed.
    #[arg(value_name = "FIXTURE", help = "Path to a v1 fixture envelope (JSON).")]
    pub fixture: PathBuf,

    /// Output directory for the default file sinks
    /// (`<DIR>/findings.txt`, `<DIR>/hardening.conf`). Created
    /// recursively when missing.
    #[arg(
        long = "output-dir",
        value_name = "DIR",
        help = "Output directory for the detailed and concise file sinks."
    )]
    pub output_dir: PathBuf,

    /// Optional report envelope v1 JSON output. When unset, the
    /// JSON sink is not selected.
    #[arg(
        long = "json",
        value_name = "PATH",
        help = "Optional path for the report envelope v1 JSON sink."
    )]
    pub json: Option<PathBuf>,

    /// Drop the default detailed (`<DIR>/findings.txt`) sink.
    #[arg(
        long = "no-detailed",
        help = "Do not write the detailed findings file.",
        default_value_t = false
    )]
    pub no_detailed: bool,

    /// Drop the default concise (`<DIR>/hardening.conf`) sink.
    #[arg(
        long = "no-concise",
        help = "Do not write the concise hardening.conf file.",
        default_value_t = false
    )]
    pub no_concise: bool,

    /// Cap on raw event TRACE lines (0 disables).
    #[arg(
        long = "max-trace-events",
        alias = "max-raw-events",
        value_name = "N",
        help = "Cap on raw event TRACE lines (0 disables).",
        default_value_t = sysdhardener_core::DEFAULT_RAW_EVENT_LOG_LIMIT
    )]
    pub max_trace_events: usize,

    /// Optional file path to write raw event TRACE lines to.
    #[arg(
        long = "trace-file",
        value_name = "PATH",
        help = "Optional file path for raw event TRACE lines."
    )]
    pub trace_file: Option<PathBuf>,

    /// Verbosity dial. Accepts `trace`, `debug`, `info`, `warn`,
    /// `error`, `off`, or `default` (which defers to `RUST_LOG`).
    /// The first occurrence wins; later occurrences are accepted
    /// but ignored, matching the "verbosity is a dial,
    /// not a confidence input" contract.
    #[arg(
        long = "verbose",
        value_name = "LEVEL",
        num_args = 0..=1,
        default_missing_value = "default",
        help = "Verbosity level: trace|debug|info|warn|error|off (default: RUST_LOG or info)."
    )]
    pub verbose: Vec<String>,
}

impl AnalyzeFixtureArgs {
    /// Return the resolved trace file path.
    #[must_use]
    pub(crate) fn trace_file_path(&self, verbosity: Verbosity) -> Option<PathBuf> {
        self.trace_file.clone().or_else(|| {
            (verbosity == Verbosity::Trace).then(|| self.output_dir.join("raw-events.log"))
        })
    }

    /// Business-level validation. Returns `Err(message)` when the
    /// caller selected no file sink at all, or when the optional
    /// `--json` path collides with a *selected* default sink's
    /// destination (a silent last-writer clobber). Both are usage
    /// errors assigned to exit code 2, owned by the binary
    /// boundary.
    pub(crate) fn validate(&self) -> Result<(), String> {
        validate_sink_selection(
            self.no_detailed,
            self.no_concise,
            self.json.as_deref(),
            &self.output_dir,
        )
    }

    /// Resolve the verbosity dial into a typed
    /// [`crate::tracing_init::Verbosity`]. Unknown strings map to
    /// `Default` (which itself falls back to `RUST_LOG` or `info`).
    /// The `Option<&str>` carries the raw unknown value so the
    /// binary can emit the fallback warning *after* the stderr
    /// subscriber is installed (a `tracing` event emitted before
    /// the subscriber exists is dropped).
    #[must_use]
    pub(crate) fn verbosity(&self) -> (Verbosity, Option<&str>) {
        resolve_verbosity(&self.verbose)
    }
}
