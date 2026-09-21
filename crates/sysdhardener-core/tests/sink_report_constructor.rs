//! `SinkWriteReport::from_attempts` constructor tests.
//!
//! These unit tests cover the disjoint-invariant check inside
//! [`SinkWriteReport::from_attempts`]: a duplicate success name
//! is rejected with a synthetic `Error::SinkWriteFailed` so the
//! binary boundary cannot ship a report that double-counts the
//! same sink.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::path::PathBuf;

use sysdhardener_core::{Error, SinkWriteFailure, SinkWriteReport};

fn sample_failure(sink: &'static str, path: &str) -> Error {
    Error::SinkWriteFailed {
        sink,
        path: PathBuf::from(path),
        kind: SinkWriteFailure::Create {
            io: "synthetic".to_owned(),
        },
    }
}

#[test]
fn from_attempts_rejects_duplicate_success_names() {
    let result = SinkWriteReport::from_attempts(
        vec![
            ("detailed", PathBuf::from("/tmp/d1")),
            ("detailed", PathBuf::from("/tmp/d2")),
        ],
        Vec::new(),
    );
    let err = result.expect_err("duplicate names are rejected");
    let Error::SinkWriteFailed { sink, .. } = &err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert_eq!(*sink, "<aggregator>");
}

#[test]
fn from_attempts_keeps_typed_paths_in_failures() {
    let failure = sample_failure("detailed", "/tmp/findings.txt");
    let report = SinkWriteReport::from_attempts(
        vec![("concise", PathBuf::from("/tmp/hardening.conf"))],
        vec![failure],
    )
    .expect("disjoint successes and failures build a valid report");
    let carried = report.failures().first().expect("one failure");
    let Error::SinkWriteFailed { sink, path, .. } = carried else {
        panic!("expected SinkWriteFailed, got {carried:?}");
    };
    assert_eq!(*sink, "detailed");
    assert_eq!(path, &PathBuf::from("/tmp/findings.txt"));
}

#[test]
fn from_attempts_accepts_disjoint_sinks_and_failures() {
    let failure = sample_failure("json", "/tmp/report.json");
    let report = SinkWriteReport::from_attempts(
        vec![
            ("detailed", PathBuf::from("/tmp/findings.txt")),
            ("concise", PathBuf::from("/tmp/hardening.conf")),
        ],
        vec![failure],
    )
    .expect("disjoint sinks + failures");
    assert_eq!(report.success_count(), 2);
    assert_eq!(report.failure_count(), 1);
}
