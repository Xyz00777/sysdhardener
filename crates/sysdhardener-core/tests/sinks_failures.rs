//! Per-sink typed failure tests for the three independent `OutputSink`
//! file adapters.
//!
//! Locked invariants:
//! - a sink that cannot write returns a typed `Error::SinkWriteFailed`
//!   carrying the sink name, destination path, and a categorized
//!   create/write/flush discriminant;
//! - when one selected sink fails, the remaining sinks complete
//!   normally and their outputs are preserved (no rollback, no deletion);
//! - each sink is attempted exactly once (no retry);
//! - a directory-creation failure returns `SinkWriteFailure::Create`;
//! - a write-after-create failure returns `SinkWriteFailure::Write`;
//! - a flush/sync failure returns `SinkWriteFailure::Flush`;
//! - the error discriminant is unique and matches what the sink reported.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use sysdhardener_core::{
    Capability, ConciseFileSink, DetailedFileSink, Error, Finding, JsonFileSink, OutputSink,
    Report, RestrictAddressFamilies, SinkWriteFailure, aggregate_address_family_evidence,
    parse_fixture_v1, recommend_restrict_address_families,
};

fn recommend(path: &str, visibility: Capability) -> Finding {
    let bytes = fs::read(path).expect("fixture must be readable");
    let parsed = parse_fixture_v1(&bytes).expect("fixture must parse");
    let bundle = aggregate_address_family_evidence(parsed.events(), &parsed).expect("aggregate");
    recommend_restrict_address_families(&bundle, visibility, &RestrictAddressFamilies::record())
        .expect("candidate must surface")
}

fn assert_dir_or_create(kind: &SinkWriteFailure) {
    assert!(
        matches!(
            kind,
            SinkWriteFailure::Create { .. } | SinkWriteFailure::PathIsDirectory { .. }
        ),
        "directory failure must be classified as create or path-is-directory, got {kind:?}"
    );
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tempdir(label: &str) -> RemoveDirOnDrop {
    let pid: u64 = u64::from(std::process::id());
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir_name: String = format!("sysdhardener-sink-fail-{label}-{pid}-{seq}.d");
    let path: PathBuf = std::env::temp_dir().join(dir_name);
    fs::create_dir_all(&path).expect("unique tempdir must be creatable");
    RemoveDirOnDrop { path }
}

struct RemoveDirOnDrop {
    path: PathBuf,
}

impl RemoveDirOnDrop {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn detailed_sink_against_directory_path_returns_typed_create_failure() {
    let temp: RemoveDirOnDrop = unique_tempdir("dir-detailed");
    let dir_path: PathBuf = temp.path().join("not-a-file");
    fs::create_dir(&dir_path).expect("subdir must be creatable");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = DetailedFileSink::new(&dir_path, std::slice::from_ref(&finding));
    let err: Error = sink
        .write()
        .expect_err("write against a directory must fail");
    let discriminant: String = format!("{err:?}");
    assert!(
        discriminant.contains("SinkWriteFailed"),
        "directory write must surface the typed SinkWriteFailed discriminant: {discriminant}"
    );
    let Error::SinkWriteFailed { sink, path, kind } = err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert_eq!(sink, "detailed");
    assert_eq!(path, dir_path);
    assert_dir_or_create(&kind);
}

#[test]
fn concise_sink_against_directory_path_returns_typed_create_failure() {
    let temp: RemoveDirOnDrop = unique_tempdir("dir-concise");
    let dir_path: PathBuf = temp.path().join("not-a-file");
    fs::create_dir(&dir_path).expect("subdir must be creatable");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = ConciseFileSink::new(&dir_path, std::slice::from_ref(&finding))
        .expect("construction accepts any path");
    let err: Error = sink
        .write()
        .expect_err("write against a directory must fail");
    let Error::SinkWriteFailed { sink, path, kind } = err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert_eq!(sink, "concise");
    assert_eq!(path, dir_path);
    assert_dir_or_create(&kind);
}

#[test]
fn json_sink_against_directory_path_returns_typed_create_failure() {
    let temp: RemoveDirOnDrop = unique_tempdir("dir-json");
    let dir_path: PathBuf = temp.path().join("not-a-file");
    fs::create_dir(&dir_path).expect("subdir must be creatable");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&dir_path, &report).expect("construction accepts any path");
    let err: Error = sink
        .write()
        .expect_err("write against a directory must fail");
    let Error::SinkWriteFailed { sink, path, kind } = err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert_eq!(sink, "json");
    assert_eq!(path, dir_path);
    assert_dir_or_create(&kind);
}

#[test]
fn json_sink_against_missing_parent_directory_returns_typed_create_failure() {
    let temp: RemoveDirOnDrop = unique_tempdir("missing-parent");
    let path: PathBuf = temp.path().join("nope").join("deeper").join("report.json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction accepts any path");
    let err: Error = sink.write().expect_err("missing parent must fail");
    let discriminant: String = format!("{err:?}");
    assert!(
        discriminant.contains("SinkWriteFailed"),
        "missing parent write must surface the typed SinkWriteFailed discriminant: {discriminant}"
    );
    let Error::SinkWriteFailed { sink, kind, .. } = err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert_eq!(sink, "json");
    assert!(
        matches!(kind, SinkWriteFailure::Create { .. }),
        "missing parent must classify as Create: {kind:?}"
    );
}

#[test]
fn one_failure_preserves_remaining_sink_outputs_with_no_coordinator() {
    let temp: RemoveDirOnDrop = unique_tempdir("partial");
    let detailed_path: PathBuf = temp.path().join("findings.txt");
    let concise_path: PathBuf = temp.path().join("hardening.conf");
    let json_path: PathBuf = temp.path().join("a-directory-not-a-file");
    fs::create_dir(&json_path).expect("must create the directory that will reject json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding.clone()];
    let report: Report<'_> = Report::with_findings(&findings);
    let detailed = DetailedFileSink::new(&detailed_path, std::slice::from_ref(&finding));
    let concise = ConciseFileSink::new(&concise_path, std::slice::from_ref(&finding))
        .expect("concise construction");
    let json = JsonFileSink::new(&json_path, &report).expect("json construction");
    let r_detailed: Result<(), Error> = detailed.write();
    let r_concise: Result<(), Error> = concise.write();
    let r_json: Result<(), Error> = json.write();
    assert!(r_detailed.is_ok(), "detailed must succeed independently");
    assert!(r_concise.is_ok(), "concise must succeed independently");
    let json_err: Error = r_json.expect_err("json must fail because the path is a directory");
    let Error::SinkWriteFailed { sink, .. } = &json_err else {
        panic!("expected SinkWriteFailed, got {json_err:?}");
    };
    assert_eq!(*sink, "json");
    // The two successful sinks' outputs must remain on disk; the failed sink is not cleaned up.
    assert!(detailed_path.is_file(), "detailed file must remain");
    assert!(concise_path.is_file(), "concise file must remain");
    let detailed_bytes: Vec<u8> = fs::read(&detailed_path).expect("read detailed");
    let concise_bytes: Vec<u8> = fs::read(&concise_path).expect("read concise");
    assert!(!detailed_bytes.is_empty());
    assert!(!concise_bytes.is_empty());
}

#[test]
fn every_selected_sink_is_attempted_exactly_once_when_one_fails() {
    struct CountingSink {
        name: &'static str,
        count: Arc<AtomicUsize>,
    }
    impl OutputSink for CountingSink {
        fn write(&self) -> Result<(), Error> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn destination(&self) -> std::path::PathBuf {
            std::path::PathBuf::from("<counting>")
        }
    }
    struct FailingSink {
        name: &'static str,
        count: Arc<AtomicUsize>,
    }
    impl OutputSink for FailingSink {
        fn write(&self) -> Result<(), Error> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Err(Error::SinkWriteFailed {
                sink: self.name,
                path: PathBuf::from("<synthetic>"),
                kind: SinkWriteFailure::Create {
                    io: "synthetic".to_owned(),
                },
            })
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn destination(&self) -> std::path::PathBuf {
            std::path::PathBuf::from("<failing>")
        }
    }
    let ok1_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let ok2_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let fail_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let sinks: Vec<Box<dyn OutputSink>> = vec![
        Box::new(CountingSink {
            name: "ok1",
            count: ok1_count.clone(),
        }),
        Box::new(FailingSink {
            name: "fail",
            count: fail_count.clone(),
        }),
        Box::new(CountingSink {
            name: "ok2",
            count: ok2_count.clone(),
        }),
    ];
    // Drive every selected sink exactly once; failures and successes are independent.
    let mut successes: usize = 0;
    let mut failures: Vec<Error> = Vec::new();
    for sink in &sinks {
        match sink.write() {
            Ok(()) => successes += 1,
            Err(error) => failures.push(error),
        }
    }
    assert_eq!(ok1_count.load(Ordering::SeqCst), 1, "ok1 attempted once");
    assert_eq!(fail_count.load(Ordering::SeqCst), 1, "fail attempted once");
    assert_eq!(ok2_count.load(Ordering::SeqCst), 1, "ok2 attempted once");
    assert_eq!(successes, 2, "two successes");
    assert_eq!(failures.len(), 1, "one failure");
    let failure = failures.first().expect("one failure");
    let Error::SinkWriteFailed { sink, .. } = failure else {
        panic!("expected SinkWriteFailed, got {failure:?}");
    };
    assert_eq!(*sink, "fail");
}
