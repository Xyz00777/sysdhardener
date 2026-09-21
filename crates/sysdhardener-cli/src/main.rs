//! `sysdhardener` CLI binary entry point.
//!
//! The binary is intentionally thin: it parses the CLI, installs
//! the stderr-only `tracing` subscriber, runs the typed
//! application seam, and maps the typed `ProcessOutcome` to an
//! `ExitCode`. Every domain decision lives in the library or in
//! the focused sibling modules (`cli`, `app`, `sinks_select`,
//! `outcome_map`, `tracing_init`); `main.rs` is the boundary
//! and the boundary only.
//!
//! Exit-code ownership:
//! - clap owns usage / parse errors (exit 2);
//! - the typed `ProcessOutcome` maps to 0 / 3 / 4 / 5 through
//!   [`sysdhardener_core::exit_code_to_u8`];
//! - the binary never calls `std::process::exit`; the boundary
//!   returns an `ExitCode` so the process-exit linter stays
//!   clean.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
// All sibling modules are reachable from `main.rs` (the binary
// entry point). They are not exposed outside the binary crate,
// so `pub(crate)` is the strictest visibility the workspace
// lints accept. The `unreachable_pub` warning is silenced at
// the bin level because the items are intentionally private
// to the binary.
#![allow(
    unreachable_pub,
    reason = "binary-crate modules and items are private to the binary by design"
)]

pub(crate) mod app;
#[cfg(feature = "bpf-observe")]
pub(crate) mod bpf_observe;
pub(crate) mod cli;
pub(crate) mod cli_observe;
pub(crate) mod outcome_map;
pub(crate) mod sinks_select;
pub(crate) mod tracing_init;

use std::process::ExitCode;

use clap::Parser;
use cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (verbosity, unknown_verbose) = match &cli.command {
        cli::Commands::AnalyzeFixture(args) => args.verbosity(),
        cli::Commands::Observe(args) => args.verbosity(),
        cli::Commands::Attach(args) => args.verbosity(),
        #[cfg(feature = "bpf-observe")]
        cli::Commands::BpfObserve(args) => args.verbosity(),
    };
    let trace_file = match &cli.command {
        cli::Commands::AnalyzeFixture(args) => args.trace_file_path(verbosity),
        cli::Commands::Observe(args) => args.trace_file_path(verbosity),
        cli::Commands::Attach(args) => args.trace_file_path(verbosity),
        #[cfg(feature = "bpf-observe")]
        cli::Commands::BpfObserve(args) => args.trace_file_path(verbosity),
    };
    let handle = tracing_init::install_subscriber(verbosity, trace_file.as_deref());
    tracing::info!(
        target: "sysdhardener.cli",
        filter = %handle.filter_directive,
        verbosity = ?handle.verbosity,
        trace_file = ?handle.trace_file,
        "tracing subscriber installed"
    );
    if let Some(raw) = unknown_verbose {
        tracing::warn!(
            target: "sysdhardener.cli",
            level = raw,
            "unknown --verbose level; falling back to RUST_LOG / info"
        );
    }
    if handle.fell_back_from_invalid_rust_log {
        tracing::warn!(
            target: "sysdhardener.cli",
            "RUST_LOG is set but empty or unparseable; falling back to info"
        );
    }

    match &cli.command {
        cli::Commands::AnalyzeFixture(args) => {
            if let Err(message) = args.validate() {
                #[allow(
                    clippy::print_stderr,
                    reason = "usage errors are formatted as human-readable CLI messages directly on stderr"
                )]
                {
                    eprintln!("usage error: {message}");
                }
                return app::exit_code_for_usage_error();
            }
            let outcome = app::run_analyze_fixture(args);
            app::write_stderr_diagnostics(&outcome);
            app::exit_code_for_outcome(&outcome)
        }
        cli::Commands::Observe(args) => {
            if let Err(message) = args.validate() {
                #[allow(
                    clippy::print_stderr,
                    reason = "usage errors are formatted as human-readable CLI messages directly on stderr"
                )]
                {
                    eprintln!("usage error: {message}");
                }
                return app::exit_code_for_usage_error();
            }
            let outcome = app::run_observe(args);
            app::write_stderr_diagnostics(&outcome);
            app::exit_code_for_outcome(&outcome)
        }
        cli::Commands::Attach(args) => {
            if let Err(message) = args.validate() {
                #[allow(
                    clippy::print_stderr,
                    reason = "usage errors are formatted as human-readable CLI messages directly on stderr"
                )]
                {
                    eprintln!("usage error: {message}");
                }
                return app::exit_code_for_usage_error();
            }
            let outcome = app::run_attach(args);
            app::write_stderr_diagnostics(&outcome);
            app::exit_code_for_outcome(&outcome)
        }
        #[cfg(feature = "bpf-observe")]
        cli::Commands::BpfObserve(args) => {
            if let Err(message) = args.validate() {
                #[allow(
                    clippy::print_stderr,
                    reason = "usage errors are formatted as human-readable CLI messages directly on stderr"
                )]
                {
                    eprintln!("usage error: {message}");
                }
                return app::exit_code_for_usage_error();
            }
            let outcome = bpf_observe::run_bpf_observe(args);
            app::write_stderr_diagnostics(&outcome);
            app::exit_code_for_outcome(&outcome)
        }
    }
}
