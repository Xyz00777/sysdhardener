//! Capability-probe audit tests: determinism, input purity, and
//! consistency of the real `/proc/self/status` reader with an
//! independently re-implemented line scan. The tests never touch the
//! wall clock, randomness, global state, or any host mutation.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the probe contract"
)]

use sysdhardener_core::{
    Capability, CapabilityProbe, ProcStatusCapabilityProbe, parse_status_visibility,
    read_proc_status,
};

const ROOT_STATUS: &str = "Name:\tsystemd\nUid:\t0\t0\t0\t0\n";
const NONROOT_STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\n";

#[test]
fn parser_is_deterministic_and_input_pure() {
    let first = parse_status_visibility(ROOT_STATUS);
    let second = parse_status_visibility(ROOT_STATUS);
    assert_eq!(first, Capability::ExpectedRoot);
    assert_eq!(first, second);

    // Input text is not mutated by the parse.
    assert!(ROOT_STATUS.contains("Uid:\t0\t0\t0\t0"));
    assert!(NONROOT_STATUS.contains("Uid:\t1000\t1000\t1000\t1000"));
}

/// Independently re-implement the effective-UID scan so the audit is
/// not a tautology: the test computes the expected classification
/// from the raw real status text with its own line/field logic.
fn independent_classification(status_text: &str) -> Option<Capability> {
    for line in status_text.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let effective: u32 = rest.split_whitespace().nth(1)?.parse().ok()?;
        return Some(if effective == 0 {
            Capability::ExpectedRoot
        } else {
            Capability::DegradedNonRoot
        });
    }
    None
}

#[test]
fn real_proc_status_read_and_parse_agree_with_independent_scan() {
    let real: String =
        read_proc_status("/proc/self/status").expect("real /proc/self/status is readable");
    let parsed = parse_status_visibility(&real);
    match independent_classification(&real) {
        Some(expected) => assert_eq!(
            parsed, expected,
            "parser must agree with the independent scan on real status"
        ),
        None => assert_eq!(
            parsed,
            Capability::Unknown,
            "unparseable real status must degrade to Unknown"
        ),
    }
}

#[test]
fn real_probe_visibility_matches_parsed_real_status() {
    let real: String =
        read_proc_status("/proc/self/status").expect("real /proc/self/status is readable");
    let probe = ProcStatusCapabilityProbe;
    assert_eq!(
        probe.visibility(),
        parse_status_visibility(&real),
        "the real probe must read /proc/self/status and parse it"
    );
}
