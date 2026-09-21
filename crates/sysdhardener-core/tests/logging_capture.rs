//! Captured-subscriber contract tests for the logging layer.
//!
//! Locked invariants:
//! - raw fixture events appear only at TRACE, never at DEBUG or higher;
//! - raw events are bounded by the explicit event-log cap; an oversized
//!   fixture logs no more than the cap and emits exactly one truncation
//!   line carrying `truncated=true` plus the logged/total/cap counts;
//! - every test installs a scoped `tracing-subscriber` with an injected
//!   `MakeWriter` backed by a synchronized byte buffer, runs the analysis
//!   through the public seam, and lets `with_default` restore the prior
//!   (no-op) thread-local default — no global subscriber races.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public logging contract"
)]

use std::fs;
use std::sync::{Arc, Mutex};

use sysdhardener_core::{
    AnalysisInput, Capability, CompatibilityRecord, DEFAULT_RAW_EVENT_LOG_LIMIT,
    RestrictAddressFamilies, run_analysis,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Synchronized byte buffer shared with the fmt subscriber through an
/// injected `MakeWriter`; every emitted log line lands here and nowhere
/// else (the writer is the only sink the test installs).
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

/// Run `f` under a scoped fmt subscriber writing to a fresh synchronized
/// buffer at `level`, then return (captured text, result). `with_default`
/// is thread-local and restores the prior default when the closure returns.
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

fn canonical_fixture_bytes() -> Vec<u8> {
    fs::read("tests/fixtures/happy.json").expect("canonical fixture must be readable")
}

const fn input_from<'a>(
    bytes: &'a [u8],
    compatibility: &'a CompatibilityRecord,
    limit: usize,
) -> AnalysisInput<'a> {
    AnalysisInput {
        fixture_bytes: bytes,
        visibility: Capability::ExpectedRoot,
        compatibility,
        raw_event_log_limit: limit,
    }
}

const fn canonical_input<'a>(
    bytes: &'a [u8],
    compatibility: &'a CompatibilityRecord,
) -> AnalysisInput<'a> {
    input_from(bytes, compatibility, DEFAULT_RAW_EVENT_LOG_LIMIT)
}

/// Build an oversized v1 fixture carrying `event_count` deterministic
/// events (unique ids, ascending timestamps, single source).
fn oversized_fixture_bytes(event_count: u32) -> Vec<u8> {
    let events: Vec<String> = (0..event_count)
        .map(|i| {
            format!(
                r#"{{"source_id":"SRC-01","event_id":"evt-{i:03}","timestamp_unix_ms":{},"address_family":"unix","outcome":"success","args":"arg-{i}"}}"#,
                1_700_000_000_000 + i64::from(i)
            )
        })
        .collect();
    let last_ms = 1_700_000_000_000 + i64::from(event_count.saturating_sub(1));
    format!(
        r#"{{"schema_version":1,"fixture_id":"oversized","first_timestamp_unix_ms":1700000000000,"last_timestamp_unix_ms":{last_ms},"coverage":"complete","seen_events":{event_count},"dropped_events":0,"events":[{}]}}"#,
        events.join(",")
    )
    .into_bytes()
}

#[test]
fn raw_events_absent_at_debug_and_present_at_trace() {
    let bytes = canonical_fixture_bytes();
    let compat = RestrictAddressFamilies::record();
    let input = canonical_input(&bytes, &compat);
    let (debug_text, _) = capture(LevelFilter::DEBUG, || {
        run_analysis(&input).expect("analysis must succeed at DEBUG")
    });
    let (trace_text, _) = capture(LevelFilter::TRACE, || {
        run_analysis(&input).expect("analysis must succeed at TRACE")
    });
    assert!(
        !debug_text.contains("event_index="),
        "raw events must never appear at DEBUG or higher"
    );
    assert_eq!(
        trace_text.matches("event_index=").count(),
        3,
        "all raw events must appear at TRACE"
    );
}

#[test]
fn raw_events_absent_at_info_level() {
    let bytes = canonical_fixture_bytes();
    let compat = RestrictAddressFamilies::record();
    let input = canonical_input(&bytes, &compat);
    let (info_text, _) = capture(LevelFilter::INFO, || {
        run_analysis(&input).expect("analysis must succeed at INFO")
    });
    assert!(
        !info_text.contains("event_index="),
        "raw events must not appear at INFO"
    );
}

#[test]
fn oversized_fixture_capped_at_limit_with_truncation_field() {
    let bytes = oversized_fixture_bytes(15);
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, &compat, 10);
    let (text, _) = capture(LevelFilter::TRACE, || {
        run_analysis(&input).expect("oversized fixture must analyze")
    });
    assert_eq!(
        text.matches("event_index=").count(),
        10,
        "raw events must stop at the explicit cap"
    );
    assert_eq!(
        text.matches("truncated=true").count(),
        1,
        "exactly one truncation line after the cap"
    );
    assert!(
        text.contains("logged=10"),
        "truncation must carry logged count"
    );
    assert!(
        text.contains("total=15"),
        "truncation must carry total count"
    );
    assert!(
        text.contains("cap=10"),
        "truncation must carry the explicit cap"
    );
}

#[test]
fn zero_cap_logs_no_raw_events_but_still_truncates() {
    let bytes = oversized_fixture_bytes(5);
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, &compat, 0);
    let (text, _) = capture(LevelFilter::TRACE, || {
        run_analysis(&input).expect("analysis must succeed with zero cap")
    });
    assert_eq!(
        text.matches("event_index=").count(),
        0,
        "zero cap must log no raw events"
    );
    assert_eq!(text.matches("truncated=true").count(), 1);
    assert!(text.contains("logged=0"));
    assert!(text.contains("total=5"));
}

#[test]
fn capped_run_does_not_suppress_raw_events_at_or_below_cap() {
    let bytes = canonical_fixture_bytes();
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, &compat, 3);
    let (text, _) = capture(LevelFilter::TRACE, || {
        run_analysis(&input).expect("analysis must succeed at cap == event count")
    });
    assert_eq!(text.matches("event_index=").count(), 3);
    assert_eq!(
        text.matches("truncated=true").count(),
        0,
        "no truncation when the fixture fits within the cap"
    );
}
