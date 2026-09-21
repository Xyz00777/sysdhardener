//! `bpf-observe` application logic (feature-gated: `bpf-observe`).
//!
//! Attaches the eBPF observer to a target cgroup and runs the
//! captured evidence through the standard analysis engine. The
//! cgroup sockaddr hooks fire pre-operation, so every event is
//! stamped `EventOutcome::Unknown`; an attempted family is a needed
//! family, so the observed families enter the `RestrictAddressFamilies=`
//! allow-list.
//!
//! This module is only compiled when the `bpf-observe` feature is
//! enabled (it pulls the aya-based loader into the binary).

use std::path::PathBuf;

use sysdhardener_core::CapabilityProbe;
use sysdhardener_core::ProcStatusCapabilityProbe;
use sysdhardener_core::ProcessOutcome;
use sysdhardener_core::RestrictAddressFamilies;

use crate::app::{analyze_observed_fixture, classify_analysis_error, finalize_summary};
use crate::sinks_select::SinkSelection;
use crate::tracing_init::Verbosity;

/// Argument set for `sysdhardener bpf-observe`.
///
/// The target is a cgroup directory (the unit's cgroup path on a
/// systemd host, e.g. `/sys/fs/cgroup/system.slice/foo.service`); the
/// loader attaches the cgroup sockaddr programs to that cgroup.
#[derive(Debug, clap::Args)]
pub struct BpfObserveArgs {
    /// Path to the compiled eBPF object (see `scripts/build-ebpf.sh`).
    #[arg(
        long = "object",
        value_name = "PATH",
        required = true,
        help = "Path to the compiled sysdhardener eBPF object (BPF ELF)."
    )]
    pub object: PathBuf,

    /// Cgroup directory to attach the sockaddr programs to.
    #[arg(
        long = "cgroup",
        value_name = "PATH",
        required = true,
        help = "Cgroup directory to attach the eBPF programs to."
    )]
    pub cgroup: PathBuf,

    /// Capture window in milliseconds.
    #[arg(
        long = "duration-ms",
        value_name = "N",
        default_value_t = 10_000,
        help = "Capture window in milliseconds (default: 10000)."
    )]
    pub duration_ms: u64,

    /// Output directory for the default file sinks.
    #[arg(
        long = "output-dir",
        value_name = "DIR",
        help = "Output directory for the detailed and concise file sinks."
    )]
    pub output_dir: PathBuf,

    /// Optional report envelope v1 JSON output.
    #[arg(
        long = "json",
        value_name = "PATH",
        help = "Optional path for the report envelope v1 JSON sink."
    )]
    pub json: Option<PathBuf>,

    /// Drop the default detailed sink.
    #[arg(
        long = "no-detailed",
        help = "Do not write the detailed findings file.",
        default_value_t = false
    )]
    pub no_detailed: bool,

    /// Drop the default concise sink.
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

    /// Verbosity dial.
    #[arg(
        long = "verbose",
        value_name = "LEVEL",
        num_args = 0..=1,
        default_missing_value = "default",
        help = "Verbosity level: trace|debug|info|warn|error|off (default: RUST_LOG or info)."
    )]
    pub verbose: Vec<String>,
}

impl BpfObserveArgs {
    /// Business-level sink validation (mirrors the other commands).
    pub(crate) fn validate(&self) -> Result<(), String> {
        crate::sinks_select::validate_sink_selection(
            self.no_detailed,
            self.no_concise,
            self.json.as_deref(),
            &self.output_dir,
        )
    }

    /// Return the resolved trace file path.
    #[must_use]
    pub(crate) fn trace_file_path(&self, verbosity: Verbosity) -> Option<PathBuf> {
        self.trace_file.clone().or_else(|| {
            (verbosity == Verbosity::Trace).then(|| self.output_dir.join("raw-events.log"))
        })
    }

    /// Resolve the verbosity dial.
    #[must_use]
    pub(crate) fn verbosity(&self) -> (Verbosity, Option<&str>) {
        self.verbose
            .first()
            .map_or((Verbosity::Default, None), |raw| {
                crate::tracing_init::parse_verbosity(raw.as_str())
            })
    }
}

/// Run one `bpf-observe` invocation.
///
/// The eBPF attach requires root/`CAP_BPF` and a BPF-enabled kernel;
/// any loader failure (object unreadable, garbage object, attach
/// denied) is a processing failure (exit 4).
#[must_use]
pub fn run_bpf_observe(args: &BpfObserveArgs) -> ProcessOutcome {
    let object_bytes = match std::fs::read(&args.object) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
                context: format!("failed to read eBPF object: {error}"),
            });
        }
    };
    let cgroup_file = match std::fs::File::open(&args.cgroup) {
        Ok(file) => file,
        Err(error) => {
            return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
                context: format!("failed to open cgroup: {error}"),
            });
        }
    };

    let sock_events = match sysdhardener_bpf_loader::observe_cgroup_events(
        &object_bytes,
        &cgroup_file,
        args.duration_ms,
    ) {
        Ok(events) => events,
        Err(error) => {
            return ProcessOutcome::ProcessingFailed(sysdhardener_core::Error::Io {
                context: format!("bpf observer failed: {error}"),
            });
        }
    };
    tracing::info!(
        target: "sysdhardener.cli",
        captured_events = sock_events.len(),
        "eBPF observation complete"
    );

    let normalized_cgroup = sysdhardener_core::normalize_path(&args.cgroup);
    let cgroup_str = normalized_cgroup.to_str().map(|s| {
        let trimmed = s.trim_end_matches('/');
        if trimmed.is_empty() { "/" } else { trimmed }
    });
    let observed =
        sysdhardener_bpf_loader::sock_events_to_observed_with_cgroup(&sock_events, cgroup_str);
    let fixture = sysdhardener_core::Fixture::from_events(observed);
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
    // The eBPF cgroup hook delivers every sockaddr stop, so there are
    // no undelivered-syscall gaps (unlike the ptrace observer).
    let summary = match analyze_observed_fixture(
        &fixture,
        visibility,
        &compatibility,
        args.max_trace_events,
        host_version,
        &[],
    ) {
        Ok(summary) => summary,
        Err(error) => return classify_analysis_error(error),
    };

    finalize_summary(&summary, &SinkSelection::from_bpf(args))
}
