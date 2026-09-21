//! Stable-field contract tests for the logging layer.
//!
//! Locked invariants:
//! - lifecycle/decision events carry stable machine field names with data
//!   in fields, never interpolation into the message;
//! - INFO carries lifecycle/summary fields, WARN carries gaps/loss and
//!   uncertain attribution, DEBUG carries aggregated evidence and mapping
//!   decisions — and the recommendation output is byte-identical across
//!   every log level (log level is a verbosity control, not confidence).
//!
//! Capture isolation (scoped subscriber restoration, cross-thread
//! independence) lives in `logging_isolation.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public logging contract"
)]

use std::fs;
use std::sync::{Arc, Mutex};

use sysdhardener_core::{
    AnalysisInput, Capability, CompatibilityRecord, DetailedEntry, Report, RestrictAddressFamilies,
    run_analysis, serialize_report_v1,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct SyncBuffer(Arc<Mutex<Vec<u8>>>);

struct SyncBufferGuard<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

impl std::io::Write for SyncBufferGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SyncBuffer {
    type Writer = SyncBufferGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        SyncBufferGuard(self.0.lock().expect("capture buffer lock"))
    }
}

fn capture<T>(level: LevelFilter, f: impl FnOnce() -> T) -> (String, T) {
    let buffer = SyncBuffer(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .without_time()
        .with_ansi(false)
        .with_writer(buffer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    let bytes = buffer.0.lock().expect("capture buffer lock").clone();
    let text = String::from_utf8(bytes).expect("captured bytes must be utf-8");
    (text, result)
}

fn fixture_bytes(path: &str) -> Vec<u8> {
    fs::read(path).expect("fixture must be readable")
}

const fn input_from<'a>(
    bytes: &'a [u8],
    visibility: Capability,
    compatibility: &'a CompatibilityRecord,
    limit: usize,
) -> AnalysisInput<'a> {
    AnalysisInput {
        fixture_bytes: bytes,
        visibility,
        compatibility,
        raw_event_log_limit: limit,
    }
}

#[test]
fn info_lifecycle_events_carry_stable_machine_fields() {
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let (text, output) = capture(LevelFilter::INFO, || {
        run_analysis(&input).expect("analysis must succeed at INFO")
    });
    assert!(
        text.contains("fixture_id=happy-3events"),
        "started line carries fixture id"
    );
    assert!(
        text.contains("schema_version=1"),
        "started line carries schema version"
    );
    assert!(
        text.contains("seen_events=3"),
        "started line carries seen count"
    );
    assert!(
        text.contains("dropped_events=0"),
        "started line carries dropped count"
    );
    assert!(
        text.contains("findings=1"),
        "completed line carries finding count"
    );
    assert_eq!(output.detailed.entries().len(), 1);
    assert_eq!(
        output.concise.lines().len(),
        2,
        "warning line + one setting line"
    );
}

#[test]
fn warn_events_fire_for_dropped_events_and_degraded_coverage() {
    let bytes = fixture_bytes("tests/fixtures/with-loss.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let (text, _) = capture(LevelFilter::WARN, || {
        run_analysis(&input).expect("analysis must succeed at WARN")
    });
    assert!(
        text.contains("dropped_events=1"),
        "dropped events must warn"
    );
    assert!(
        text.contains("coverage="),
        "degraded coverage must carry a coverage field"
    );
}

#[test]
fn warn_events_fire_for_degraded_visibility() {
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::DegradedNonRoot, &compat, 10);
    let (text, output) = capture(LevelFilter::WARN, || {
        run_analysis(&input).expect("analysis must succeed under degraded visibility")
    });
    assert!(
        text.contains("visibility="),
        "degraded visibility must warn"
    );
    assert_eq!(
        output.finding.coverage(),
        sysdhardener_core::CoverageQuality::Degraded,
        "visibility degrades effective coverage, never hides the candidate"
    );
}

#[test]
fn debug_events_carry_aggregate_and_mapping_fields() {
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let (text, _) = capture(LevelFilter::DEBUG, || {
        run_analysis(&input).expect("analysis must succeed at DEBUG")
    });
    assert_eq!(
        text.matches("aggregate_key=").count(),
        3,
        "one aggregate line per family"
    );
    assert!(
        text.contains("aggregate_count="),
        "aggregate line carries count"
    );
    assert!(
        text.contains("directive=RestrictAddressFamilies"),
        "mapping line carries directive"
    );
    assert!(text.contains("basis="), "mapping line carries basis");
    assert!(
        text.contains("provisional="),
        "mapping line carries provisional status"
    );
    assert!(
        text.contains("recommended_families="),
        "mapping line carries recommended families"
    );
}

#[test]
fn recommendation_output_identical_across_all_log_levels() {
    type Surface = (Vec<u8>, Vec<DetailedEntry>, Vec<String>);
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let mut surfaces: Vec<Surface> = Vec::new();
    for level in [
        LevelFilter::OFF,
        LevelFilter::ERROR,
        LevelFilter::WARN,
        LevelFilter::INFO,
        LevelFilter::DEBUG,
        LevelFilter::TRACE,
    ] {
        let (_text, output) = capture(level, || {
            run_analysis(&input).expect("analysis must succeed at every level")
        });
        let report =
            serialize_report_v1(&Report::with_findings(&[output.finding])).expect("serialize");
        surfaces.push((
            report,
            output.detailed.entries().to_vec(),
            output.concise.lines().to_vec(),
        ));
    }
    if let Some(baseline) = surfaces.first() {
        for surface in surfaces.iter().skip(1) {
            assert_eq!(baseline, surface, "output must not vary with log level");
        }
    }
}
