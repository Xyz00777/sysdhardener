//! Capture-isolation tests for the logging layer.
//!
//! Locked invariants:
//! - a scoped captured subscriber restores the prior thread-local default,
//!   so events logged after the scope ends never write into the retired
//!   buffer;
//! - captures are independent per thread: raw-event visibility in one
//!   capture never leaks into another, sequentially or in parallel.
//!
//! Stable-field contracts live in `logging_contract.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public logging contract"
)]

use std::fs;
use std::sync::{Arc, Mutex};

use sysdhardener_core::{
    AnalysisInput, Capability, CompatibilityRecord, RestrictAddressFamilies, run_analysis,
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
fn scoped_subscriber_restores_prior_default_state() {
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let buffer = SyncBuffer(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .without_time()
        .with_ansi(false)
        .with_writer(buffer.clone())
        .finish();
    let captured_len = tracing::subscriber::with_default(subscriber, || {
        run_analysis(&input).expect("analysis must succeed inside the scoped subscriber");
        buffer.0.lock().expect("capture buffer lock").len()
    });
    assert!(captured_len > 0, "scoped subscriber must capture the run");
    tracing::info!(target: "sysdhardener.analysis", "post-capture");
    let len_after = buffer.0.lock().expect("capture buffer lock").len();
    assert_eq!(
        len_after, captured_len,
        "restored no-op default must not write into the retired buffer"
    );
}

#[test]
fn captures_are_isolated_across_sequential_and_parallel_runs() {
    let bytes = fixture_bytes("tests/fixtures/happy.json");
    let compat = RestrictAddressFamilies::record();
    let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
    let (trace_text, _) = capture(LevelFilter::TRACE, || {
        run_analysis(&input).expect("analysis must succeed at TRACE")
    });
    let (info_text, _) = capture(LevelFilter::INFO, || {
        run_analysis(&input).expect("analysis must succeed at INFO")
    });
    assert!(
        trace_text.contains("event_index="),
        "TRACE capture sees raw events"
    );
    assert!(
        !info_text.contains("event_index="),
        "INFO capture must not inherit TRACE state"
    );
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                let bytes = fixture_bytes("tests/fixtures/happy.json");
                let compat = RestrictAddressFamilies::record();
                let input = input_from(&bytes, Capability::ExpectedRoot, &compat, 10);
                let (text, _) = capture(LevelFilter::TRACE, || {
                    run_analysis(&input).expect("analysis must succeed on worker thread")
                });
                assert_eq!(
                    text.matches("event_index=").count(),
                    3,
                    "each thread sees exactly its own raw events"
                );
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("capture thread must finish");
    }
}
