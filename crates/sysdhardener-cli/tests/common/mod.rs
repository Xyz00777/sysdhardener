//! Shared helpers for the `analyze-fixture` E2E test split.
//!
//! Every test in `cli_analyze_fixture_*` uses a unique
//! process-private tempdir so two concurrent test processes
//! cannot collide; every tempdir is removed on drop. The
//! `cargo_bin` path is the canonical binary location Cargo
//! supplies to integration tests.

#![allow(
    unreachable_pub,
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration-test helper module is intentionally shared by sibling test crates, each of which uses only a subset of the helpers"
)]

use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::cargo_bin;

/// Per-test unique process-private tempdir. The atomic counter
/// plus the process ID guarantee uniqueness across concurrent
/// test processes, satisfying the multi-checkout / multi-agent
/// isolation invariant.
pub fn unique_tempdir(label: &str) -> tempfile::TempDir {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("sysdhardener-cli-{label}-{pid}-{counter}-{}", uuid_like());
    tempfile::Builder::new()
        .prefix(&name)
        .tempdir()
        .expect("tempdir should build for CLI test")
}

/// Deterministic per-counter suffix that does not require a UUID
/// dependency. Two callers with the same label/pid/counter still
/// land in different directories because the counter is atomic.
fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:x}")
}

/// Path to the canonical happy fixture. The CLI tests walk up to
/// the workspace crate root to find the canonical fixture file
/// the library tests use.
pub fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("sysdhardener-core");
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    path
}

/// Path to the canonical binary.
pub fn binary_path() -> PathBuf {
    cargo_bin("sysdhardener")
}

/// Captured outcome of one binary invocation: the process exit
/// code plus the decoded stdout and stderr bytes. Tests assert on
/// exit codes and machine fields only.
#[derive(Debug)]
pub struct RunOutcome {
    /// The process exit code (`None` when the process was killed by
    /// a signal, which no narrative scenario expects).
    pub code: Option<i32>,
    /// Decoded stdout bytes.
    pub stdout: String,
    /// Decoded stderr bytes.
    pub stderr: String,
}

/// Run the canonical binary once with the given argument list.
/// Every narrative E2E scenario drives the binary through this
/// single seam so the scenarios stay on the public CLI surface.
pub fn run_bin(args: &[&OsStr]) -> RunOutcome {
    let output = Command::new(binary_path())
        .args(args)
        .output()
        .expect("binary should run for CLI test");
    RunOutcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Sorted file names in a directory, used to prove residue-free
/// output: a scenario's success must leave exactly the declared
/// artifacts and nothing else.
pub fn dir_entries(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .expect("output dir readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}
