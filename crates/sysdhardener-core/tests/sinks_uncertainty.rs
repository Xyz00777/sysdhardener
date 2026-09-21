//! JSON-file-sink uncertainty preservation tests.
//!
//! Independent of the happy-path tests: the JSON file sink must
//! preserve the typed provenance / uncertainty surface (coverage,
//! compatibility risk, source IDs, event-loss counts) through the
//! wire round-trip.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sysdhardener_core::{
    Capability, ConciseFileSink, DetailedFileSink, Finding, JsonFileSink, OutputSink, Report,
    RestrictAddressFamilies, aggregate_address_family_evidence, parse_fixture_v1,
    recommend_restrict_address_families,
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
    let dir_name: String = format!("sysdhardener-sink-unc-{label}-{pid}-{seq}.d");
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
fn all_three_sinks_succeed_independently_against_distinct_unique_paths() {
    let temp: RemoveDirOnDrop = unique_tempdir("all");
    let detailed_path: PathBuf = temp.path().join("findings.txt");
    let concise_path: PathBuf = temp.path().join("hardening.conf");
    let json_path: PathBuf = temp.path().join("report.json");
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
    assert!(detailed_path.is_file(), "detailed file must exist");
    assert!(concise_path.is_file(), "concise file must exist");
    assert!(json_path.is_file(), "json file must exist");
    let detailed_bytes: Vec<u8> = fs::read(&detailed_path).expect("read detailed");
    let concise_bytes: Vec<u8> = fs::read(&concise_path).expect("read concise");
    let json_bytes: Vec<u8> = fs::read(&json_path).expect("read json");
    assert!(
        !detailed_bytes.is_empty(),
        "detailed file must be non-empty"
    );
    assert!(!concise_bytes.is_empty(), "concise file must be non-empty");
    assert!(!json_bytes.is_empty(), "json file must be non-empty");
    assert_ne!(
        detailed_bytes.first().copied(),
        concise_bytes.first().copied(),
        "detailed and concise must not be byte-identical"
    );
    let _ = detailed_bytes;
    let _ = concise_bytes;
    let _ = json_bytes;
}

#[test]
fn json_file_sink_preserves_uncertainty_for_degraded_finding() {
    let temp: RemoveDirOnDrop = unique_tempdir("json-degraded");
    let path: PathBuf = temp.path().join("report.json");
    let finding: Finding = recommend("tests/fixtures/degraded.json", Capability::DegradedNonRoot);
    let findings = [finding];
    let report: Report<'_> = Report::with_findings(&findings);
    let sink = JsonFileSink::new(&path, &report).expect("construction");
    sink.write().expect("write");
    let bytes: Vec<u8> = fs::read(&path).expect("read");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let f: &serde_json::Value = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| arr.first())
        .expect("one finding");
    let coverage: &str = f
        .get("coverage")
        .and_then(serde_json::Value::as_str)
        .expect("coverage must serialize");
    assert_eq!(
        coverage, "degraded",
        "degraded finding must persist its coverage label: {f}"
    );
    let compat: &serde_json::Value = f
        .get("compatibility_risk")
        .expect("compatibility_risk must serialize");
    let verification: &str = compat
        .get("verification")
        .and_then(serde_json::Value::as_str)
        .expect("compatibility_risk.verification must serialize as a string");
    let support: &str = compat
        .get("support")
        .and_then(serde_json::Value::as_str)
        .expect("compatibility_risk.support must serialize as a string");
    let derived_unverified: bool = support != "supported" || verification != "verified";
    assert!(
        derived_unverified,
        "the degraded finding's compatibility risk must surface its unverified-derived flag: {compat}"
    );
}
