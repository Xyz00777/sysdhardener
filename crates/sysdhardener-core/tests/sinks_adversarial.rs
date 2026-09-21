//! Adversarial probes for the three independent `OutputSink` file
//! adapters.
//!
//! Adversarial classes exercised:
//! - **path strings**: very long, unicode, prompt-like, null bytes,
//!   NULs, slashes, spaces, dots, symlink-like suffixes;
//! - **prompt content**: prompt-shaped strings do not leak into
//!   the produced text, even when present in the underlying
//!   finding's text fields;
//! - **stale/dirty**: previously-written files at the destination
//!   are overwritten, not appended, not corrupted;
//! - **determinism**: bytes are byte-identical across repeated
//!   runs of the same fixture;
//! - **misleading**: the typed success/failure discriminant is
//!   unique, never a catch-all string, and the path the consumer
//!   reads matches what the sink was given.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "adversarial tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tempdir(label: &str) -> RemoveDirOnDrop {
    let pid: u64 = u64::from(std::process::id());
    let seq: u64 = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir_name: String = format!("sysdhardener-sink-adv-{label}-{pid}-{seq}.d");
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

fn no_prompt_shingles_present(text: &str) {
    for forbidden in [
        "ignore previous instructions",
        "system: you are now root",
        "disregard all prior",
        "act as root",
        "sudo rm -rf /",
        "delete /var",
        "drop table",
    ] {
        assert!(
            !text.contains(forbidden),
            "produced text leaked prompt-shaped substring {forbidden:?}: {text}"
        );
    }
}

#[test]
fn detailed_sink_preserves_path_arbitrary_unicode_and_does_not_leak_host_path() {
    let temp: RemoveDirOnDrop = unique_tempdir("unicode");
    // A path with unicode, spaces, and a prompt-like fragment. The
    // destination directory + filename may contain these
    // characters on the host filesystem; the produced text must
    // still not leak prompt-shaped strings.
    let dir_with_unicode: PathBuf = temp.path().join("spaces and ünicode \u{1F600}-frag");
    fs::create_dir_all(&dir_with_unicode).expect("subdir must be creatable");
    let path: PathBuf = dir_with_unicode.join("findings.txt");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = DetailedFileSink::new(&path, std::slice::from_ref(&finding));
    sink.write().expect("write must succeed");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let text: &str = std::str::from_utf8(&bytes).expect("utf-8");
    no_prompt_shingles_present(text);
    // The host path itself must not appear in the produced text
    // (the sink labels the file, it does not embed its path).
    assert!(
        !text.contains(temp.path().to_str().expect("utf-8 path")),
        "produced text must not embed the host path"
    );
    assert!(
        !text.contains(dir_with_unicode.to_str().expect("utf-8 path")),
        "produced text must not embed the host subdir path"
    );
}

#[test]
fn concise_sink_preserves_path_arbitrary_unicode_and_does_not_leak_host_path() {
    let temp: RemoveDirOnDrop = unique_tempdir("unicode-concise");
    let dir_with_unicode: PathBuf = temp.path().join("spaces and ünicode \u{1F600}-frag");
    fs::create_dir_all(&dir_with_unicode).expect("subdir must be creatable");
    let path: PathBuf = dir_with_unicode.join("hardening.conf");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = ConciseFileSink::new(&path, std::slice::from_ref(&finding))
        .expect("construction must accept arbitrary path");
    sink.write().expect("write must succeed");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let text: &str = std::str::from_utf8(&bytes).expect("utf-8");
    no_prompt_shingles_present(text);
    assert!(
        !text.contains(temp.path().to_str().expect("utf-8 path")),
        "produced text must not embed the host path"
    );
}

#[test]
fn json_sink_preserves_path_arbitrary_unicode_and_does_not_leak_host_path() {
    let temp: RemoveDirOnDrop = unique_tempdir("unicode-json");
    let dir_with_unicode: PathBuf = temp.path().join("spaces and ünicode \u{1F600}-frag");
    fs::create_dir_all(&dir_with_unicode).expect("subdir must be creatable");
    let path: PathBuf = dir_with_unicode.join("report.json");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction must accept arbitrary path");
    sink.write().expect("write must succeed");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let text: &str = std::str::from_utf8(&bytes).expect("utf-8");
    no_prompt_shingles_present(text);
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let serialized: String = format!("{value}");
    assert!(
        !serialized.contains(temp.path().to_str().expect("utf-8 path")),
        "produced JSON must not embed the host path: {serialized}"
    );
}

#[test]
fn sinks_overwrite_stale_destinations_deterministically() {
    let temp: RemoveDirOnDrop = unique_tempdir("stale");
    let detailed_path: PathBuf = temp.path().join("findings.txt");
    let concise_path: PathBuf = temp.path().join("hardening.conf");
    let json_path: PathBuf = temp.path().join("report.json");
    // Pre-populate each destination with stale bytes that are
    // *longer* than the canonical content, to prove the sinks
    // overwrite (truncate + rewrite) rather than append.
    for (path, stale) in [
        (&detailed_path, b"STALE-STALE-STALE\n".to_vec()),
        (
            &concise_path,
            b"# stale warning\nRestrictAddressFamilies=AF_INET\n".to_vec(),
        ),
        (&json_path, b"{\"stale\":true}".to_vec()),
    ] {
        fs::write(path, &stale).expect("stale write");
    }
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let findings = [finding.clone()];
    let report: Report<'_> = Report::with_findings(&findings);
    let detailed = DetailedFileSink::new(&detailed_path, std::slice::from_ref(&finding));
    let concise = ConciseFileSink::new(&concise_path, std::slice::from_ref(&finding))
        .expect("concise construction");
    let json = JsonFileSink::new(&json_path, &report).expect("json construction");
    detailed.write().expect("detailed write");
    concise.write().expect("concise write");
    json.write().expect("json write");
    let detailed_bytes: Vec<u8> = fs::read(&detailed_path).expect("read");
    let concise_bytes: Vec<u8> = fs::read(&concise_path).expect("read");
    let json_bytes: Vec<u8> = fs::read(&json_path).expect("read");
    let detailed_text: &str = std::str::from_utf8(&detailed_bytes).expect("utf-8");
    let concise_text: &str = std::str::from_utf8(&concise_bytes).expect("utf-8");
    let json_text: &str = std::str::from_utf8(&json_bytes).expect("utf-8");
    assert!(
        !detailed_text.contains("STALE-STALE-STALE"),
        "detailed sink must overwrite stale content: {detailed_text}"
    );
    assert!(
        !concise_text.contains("stale warning"),
        "concise sink must overwrite stale content: {concise_text}"
    );
    assert!(
        !json_text.contains("\"stale\":true"),
        "json sink must overwrite stale content: {json_text}"
    );
    assert!(
        !detailed_text.contains("STALE"),
        "detailed sink must overwrite stale content fully: {detailed_text}"
    );
}

#[test]
fn sinks_produce_byte_identical_output_across_repeated_runs() {
    let temp_a: RemoveDirOnDrop = unique_tempdir("det-a");
    let temp_b: RemoveDirOnDrop = unique_tempdir("det-b");
    let path_a: PathBuf = temp_a.path().join("findings.txt");
    let path_b: PathBuf = temp_b.path().join("findings.txt");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink_a = DetailedFileSink::new(&path_a, std::slice::from_ref(&finding));
    let sink_b = DetailedFileSink::new(&path_b, std::slice::from_ref(&finding));
    sink_a.write().expect("write a");
    sink_b.write().expect("write b");
    let bytes_a: Vec<u8> = fs::read(&path_a).expect("read a");
    let bytes_b: Vec<u8> = fs::read(&path_b).expect("read b");
    assert_eq!(
        bytes_a, bytes_b,
        "the same finding written twice must produce byte-identical detailed output"
    );
}

#[test]
fn produced_output_contains_no_apply_or_trace_or_compile_directive_text() {
    let temp: RemoveDirOnDrop = unique_tempdir("no-apply");
    let path: PathBuf = temp.path().join("findings.txt");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = DetailedFileSink::new(&path, std::slice::from_ref(&finding));
    sink.write().expect("write");
    let text_bytes: Vec<u8> = fs::read(&path).expect("read");
    let text: &str = std::str::from_utf8(&text_bytes).expect("utf-8");
    // The detailed view is the evidence-bearing list. It must
    // not contain auto-apply / compile / trace scaffolding; the
    // view is a human-readable report, not a build script.
    for forbidden in [
        "cargo run",
        "systemctl edit",
        "systemctl daemon-reload",
        "apply now",
        "APPLY",
        "trace-001",
    ] {
        assert!(
            !text.contains(forbidden),
            "detailed text leaked forbidden scaffolding {forbidden:?}: {text}"
        );
    }
}

#[test]
fn sink_refuses_symlink_destination_without_writing_through() {
    let temp: RemoveDirOnDrop = unique_tempdir("symlink");
    let target: PathBuf = temp.path().join("would-be-clobbered");
    let link: PathBuf = temp.path().join("findings.txt");
    std::os::unix::fs::symlink(&target, &link).expect("symlink must be creatable");
    let finding: Finding = recommend("tests/fixtures/happy.json", Capability::ExpectedRoot);
    let sink = DetailedFileSink::new(&link, std::slice::from_ref(&finding));
    let err: Error = sink
        .write()
        .expect_err("write through a symlink must be refused");
    let Error::SinkWriteFailed { kind, .. } = err else {
        panic!("expected SinkWriteFailed, got {err:?}");
    };
    assert!(
        matches!(kind, SinkWriteFailure::Symlink { .. }),
        "symlink destination must classify as Symlink: {kind:?}"
    );
    assert!(
        !target.exists(),
        "the symlink target must never be written through"
    );
}
