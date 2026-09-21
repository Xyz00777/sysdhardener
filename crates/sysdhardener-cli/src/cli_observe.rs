//! CLI argument definitions for `observe` and `attach` subcommands.

use std::path::PathBuf;

use crate::sinks_select::validate_sink_selection;
use crate::tracing_init::{Verbosity, resolve_verbosity};

/// The argument set for `sysdhardener attach`: the target PID to
/// attach to and the output surface (mirrors `observe`).
#[derive(Debug, clap::Args)]
pub struct AttachArgs {
    /// The PID of the running process to attach to.
    #[arg(
        value_name = "PID",
        required = true,
        help = "The pid of the running process to observe."
    )]
    pub pid: u32,

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

    /// Include per-process pid attribution in the detailed findings.
    #[arg(
        long = "show-pids",
        help = "Include the observed pids in the detailed findings.",
        default_value_t = false
    )]
    pub show_pids: bool,

    /// Bounded duration window in milliseconds to observe before detaching.
    #[arg(
        long = "duration-ms",
        value_name = "MS",
        help = "Observation duration in ms before detaching."
    )]
    pub duration_ms: Option<u64>,

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
    /// `error`, `off`, or `default`.
    #[arg(
        long = "verbose",
        value_name = "LEVEL",
        num_args = 0..=1,
        default_missing_value = "default",
        help = "Verbosity level: trace|debug|info|warn|error|off (default: RUST_LOG or info)."
    )]
    pub verbose: Vec<String>,
}

impl AttachArgs {
    /// Return the resolved trace file path.
    #[must_use]
    pub fn trace_file_path(&self, verbosity: Verbosity) -> Option<PathBuf> {
        self.trace_file.clone().or_else(|| {
            (verbosity == Verbosity::Trace).then(|| self.output_dir.join("raw-events.log"))
        })
    }

    /// Business-level validation: at least one file sink must be
    /// selected, and `--json` must not collide with a selected
    /// default sink's destination.
    pub fn validate(&self) -> Result<(), String> {
        if self.pid == 0 || i32::try_from(self.pid).is_err() {
            return Err("target pid must be positive and non-zero".to_owned());
        }
        validate_sink_selection(
            self.no_detailed,
            self.no_concise,
            self.json.as_deref(),
            &self.output_dir,
        )
    }

    /// Resolve the verbosity dial into a typed
    /// [`crate::tracing_init::Verbosity`].
    #[must_use]
    pub fn verbosity(&self) -> (Verbosity, Option<&str>) {
        resolve_verbosity(&self.verbose)
    }
}

/// The argument set for `sysdhardener observe`. The command is the
/// program to run under observation (variadic, so arguments are
/// passed through); the output surface mirrors `analyze-fixture`.
#[derive(Debug, clap::Args)]
pub struct ObserveArgs {
    /// The command to run under observation, with its arguments.
    #[arg(
        value_name = "COMMAND",
        required = true,
        num_args = 1..,
        trailing_var_arg = true,
        help = "The program to run under observation, with its arguments."
    )]
    pub command: Vec<String>,

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

    /// Include per-process (pid) attribution in the detailed findings
    /// when the evidence was captured live by the observer. Fixture
    /// events have no pid and are unaffected.
    #[arg(
        long = "show-pids",
        help = "Include the observing process tree's pids in the detailed findings.",
        default_value_t = false
    )]
    pub show_pids: bool,

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
    /// but ignored.
    #[arg(
        long = "verbose",
        value_name = "LEVEL",
        num_args = 0..=1,
        default_missing_value = "default",
        help = "Verbosity level: trace|debug|info|warn|error|off (default: RUST_LOG or info)."
    )]
    pub verbose: Vec<String>,
}

impl ObserveArgs {
    /// Return the resolved trace file path.
    #[must_use]
    pub fn trace_file_path(&self, verbosity: Verbosity) -> Option<PathBuf> {
        self.trace_file.clone().or_else(|| {
            (verbosity == Verbosity::Trace).then(|| self.output_dir.join("raw-events.log"))
        })
    }

    /// Business-level validation: at least one file sink must be
    /// selected, and `--json` must not collide with a selected
    /// default sink's destination.
    pub fn validate(&self) -> Result<(), String> {
        validate_sink_selection(
            self.no_detailed,
            self.no_concise,
            self.json.as_deref(),
            &self.output_dir,
        )
    }

    /// Resolve the verbosity dial into a typed
    /// [`crate::tracing_init::Verbosity`].
    #[must_use]
    pub fn verbosity(&self) -> (Verbosity, Option<&str>) {
        resolve_verbosity(&self.verbose)
    }
}
