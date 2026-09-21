//! Typed `ProcessOutcome` and exit-mapping table tests.
//!
//! The typed application outcome maps to exit codes 0/3/4/5; the `NoSelectedFileSink` case is
//! a usage error and is therefore mapped to exit code 2 by the
//! binary, not the library. The library exposes the typed variants
//! and the numeric mapping function; the binary does the boundary
//! conversion. `usage_exit_code()` is the explicit value the binary
//! uses when no sink is selected.
//!
//! Acceptance criteria locked by this file:
//! - `ProcessOutcome` is a typed enum; every variant is a discriminant
//!   that carries the data the consumer matches on;
//! - `exit_code_to_u8(&ProcessOutcome) -> u8` is total and exhaustive;
//! - the mapping is `Success -> 0`, `InvalidInput -> 3`,
//!   `ProcessingFailed -> 4`, `SinkWritePartialFailure -> 5`;
//! - `usage_exit_code() -> u8` returns 2 for the no-selected-sink
//!   case the binary hands back from clap;
//! - `ProcessOutcome` carries no embedded `&'static str` messages; the
//!   only prose is the `Display` formatting used by callers that need
//!   a one-line diagnostic.
//!
//! These are unit tests for the boundary mapping.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::path::PathBuf;

use sysdhardener_core::{
    Error, ProcessOutcome, SinkWriteFailure, SinkWriteReport, exit_code_to_u8, usage_exit_code,
};

fn sample_sink_failure(sink: &'static str, path: &str) -> Error {
    Error::SinkWriteFailed {
        sink,
        path: PathBuf::from(path),
        kind: SinkWriteFailure::Create {
            io: "synthetic".to_owned(),
        },
    }
}

#[test]
fn success_outcome_maps_to_exit_zero() {
    let outcome = ProcessOutcome::Success;
    assert_eq!(exit_code_to_u8(&outcome), 0);
}

#[test]
fn invalid_input_outcome_carries_typed_error_and_maps_to_three() {
    let error = Error::SchemaUnknown {
        found: 999,
        supported: &[1],
    };
    let outcome = ProcessOutcome::InvalidInput(error);
    assert_eq!(exit_code_to_u8(&outcome), 3);
    let ProcessOutcome::InvalidInput(carried) = outcome else {
        panic!("expected InvalidInput variant");
    };
    let Error::SchemaUnknown { found, supported } = carried else {
        panic!("expected SchemaUnknown, got {carried:?}");
    };
    assert_eq!(found, 999);
    assert_eq!(supported, &[1]);
}

#[test]
fn processing_failed_outcome_carries_typed_error_and_maps_to_four() {
    let error = Error::CoverageTagUnknown("bogus".to_owned());
    let outcome = ProcessOutcome::ProcessingFailed(error);
    assert_eq!(exit_code_to_u8(&outcome), 4);
    let ProcessOutcome::ProcessingFailed(carried) = outcome else {
        panic!("expected ProcessingFailed variant");
    };
    let Error::CoverageTagUnknown(tag) = carried else {
        panic!("expected CoverageTagUnknown, got {carried:?}");
    };
    assert_eq!(tag, "bogus");
}

#[test]
fn sink_write_partial_failure_outcome_carries_typed_report_and_maps_to_five() {
    let report = SinkWriteReport::from_attempts(
        Vec::new(),
        vec![sample_sink_failure("detailed", "/tmp/findings.txt")],
    )
    .expect("one failure must build a valid report");
    let outcome = ProcessOutcome::SinkWritePartialFailure(report);
    assert_eq!(exit_code_to_u8(&outcome), 5);
    let ProcessOutcome::SinkWritePartialFailure(carried) = outcome else {
        panic!("expected SinkWritePartialFailure variant");
    };
    assert_eq!(carried.failures().len(), 1);
    assert!(carried.successes().is_empty());
}

#[test]
fn usage_exit_code_is_two() {
    assert_eq!(usage_exit_code(), 2);
}

#[test]
fn all_outcome_variants_match_the_table() {
    let cases: Vec<(ProcessOutcome, u8, &str)> = vec![
        (ProcessOutcome::Success, 0, "Success"),
        (
            ProcessOutcome::InvalidInput(Error::EventIdEmpty { index: 0 }),
            3,
            "InvalidInput",
        ),
        (
            ProcessOutcome::ProcessingFailed(Error::EventCountMismatch {
                declared: 1,
                actual: 2,
            }),
            4,
            "ProcessingFailed",
        ),
        (
            ProcessOutcome::SinkWritePartialFailure(
                SinkWriteReport::from_attempts(
                    Vec::new(),
                    vec![sample_sink_failure("json", "/tmp/report.json")],
                )
                .expect("valid one-failure report"),
            ),
            5,
            "SinkWritePartialFailure",
        ),
    ];
    for (outcome, expected_code, label) in cases {
        assert_eq!(
            exit_code_to_u8(&outcome),
            expected_code,
            "{label} must map to {expected_code}"
        );
    }
}
