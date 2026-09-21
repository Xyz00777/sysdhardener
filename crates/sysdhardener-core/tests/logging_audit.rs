//! Structural audit tests for the logging layer.
//!
//! Locked invariants:
//! - raw-event emission lives in exactly one budget type (`RawEventLog`)
//!   and uses only the TRACE level macro — never DEBUG or higher;
//! - the analysis seam emits lifecycle/decision events at
//!   INFO/WARN/DEBUG and never emits raw events itself (they flow through
//!   the budget);
//! - the new modules never touch stdio directly: all logging flows
//!   through `tracing` into whatever writer the process installs
//!   (stderr for the CLI, an injected writer in tests), keeping the
//!   diagnostic stream separate from report outputs;
//! - the analysis seam stays free of sink orchestration and process
//!   outcomes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public logging contract"
)]

use std::fs;

fn module_source(module: &str) -> String {
    fs::read_to_string(format!("src/{module}.rs"))
        .expect("module source must be readable for the structural audit")
}

#[test]
fn raw_event_emission_is_trace_only_and_lives_in_one_budget_type() {
    let src = module_source("logging");
    assert!(src.contains("tracing::trace!"), "raw emission must exist");
    for forbidden in [
        "tracing::debug!",
        "tracing::info!",
        "tracing::warn!",
        "tracing::error!",
    ] {
        assert!(
            !src.contains(forbidden),
            "RawEventLog must emit raw events only at TRACE: {forbidden}"
        );
    }
    assert_eq!(
        src.matches("impl RawEventLog").count(),
        1,
        "exactly one bounded raw-event budget type"
    );
}

#[test]
fn analysis_seam_emits_lifecycle_decision_levels_but_never_raw_trace() {
    let src = module_source("analysis");
    for required in ["tracing::info!", "tracing::warn!", "tracing::debug!"] {
        assert!(
            src.contains(required),
            "analysis seam must emit at {required}"
        );
    }
    assert!(
        !src.contains("tracing::trace!"),
        "raw events must flow through RawEventLog, never be emitted inline"
    );
}

#[test]
fn new_modules_never_touch_stdio_directly() {
    for module in ["logging", "analysis"] {
        let src = module_source(module);
        for forbidden in [
            "println!",
            "print!",
            "eprintln!",
            "eprint!",
            "std::io::stdout",
            "std::io::stderr",
            "Stdout",
            "Stderr",
        ] {
            assert!(
                !src.contains(forbidden),
                "{module} must route diagnostics through tracing only: {forbidden}"
            );
        }
    }
}

#[test]
fn analysis_seam_stays_free_of_sink_orchestration_and_process_outcomes() {
    let src = module_source("analysis");
    for forbidden in [
        "OutputSink",
        "DetailedFileSink",
        "ConciseFileSink",
        "JsonFileSink",
        "ExitCode",
        "process::exit",
        "std::process",
    ] {
        assert!(
            !src.contains(forbidden),
            "analysis seam must stay sink/exit-free: {forbidden}"
        );
    }
}
