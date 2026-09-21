//! Audit-time probes for the address-family aggregator.
//!
//! The aggregator is the only place in the deterministic slice that
//! builds the recommendation-local evidence bundle. These tests
//! prove:
//! - the aggregator does not depend on wall clock, randomness, or
//!   remote/network/runtime resources;
//! - the aggregator does not introduce a global cache, a shared
//!   evidence index, or a persistence layer;
//! - the aggregator's key serialization is the explicit stable
//!   snake-case form (no `DefaultHasher`-derived numeric fingerprint).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "audit tests use expect/unwrap/panic for direct assertions on structural invariants"
)]

use std::fs;

use sysdhardener_core::{aggregate_address_family_evidence, parse_fixture_v1};

const SRC_ROOT: &str = "src";

fn load_canonical(path: &str) -> Vec<u8> {
    fs::read(path)
        .unwrap_or_else(|e| panic!("canonical fixture {path} must be readable for audit: {e}"))
}

#[test]
fn aggregate_module_does_not_read_filesystem_or_network_at_runtime() {
    // The aggregator builds a typed bundle from a typed event slice
    // and a typed fixture. It must not touch the filesystem, the
    // network, the wall clock, or any random source.
    let pattern_module = format!("{SRC_ROOT}/aggregate.rs");
    let bytes_present = fs::read_to_string(&pattern_module).unwrap_or_default();
    assert!(
        !bytes_present.is_empty(),
        "src/aggregate.rs must exist for the aggregate contract"
    );
    for forbidden in [
        "fs::read",
        "fs::read_to_string",
        "std::fs::read",
        "std::fs::read_to_string",
        "File::open",
        "std::fs::File",
        "reqwest",
        "ureq",
        "attohttpc",
        "hyper",
        "tokio::",
        "async_std",
        "smol_",
        "Instant::now",
        "SystemTime::now",
        "rand::",
        "getrandom",
        "DefaultHasher",
        "Hasher::",
    ] {
        assert!(
            !bytes_present.contains(forbidden),
            "src/aggregate.rs must not contain {forbidden:?}; found in {pattern_module}"
        );
    }
}

#[test]
fn aggregate_module_has_no_global_state_or_persistence_marker() {
    // The aggregator must not introduce a static cache, a global
    // counter, a OnceCell, a Mutex, a database, or a "skip cache"
    // marker.
    let bytes = fs::read_to_string("src/aggregate.rs")
        .expect("src/aggregate.rs must be readable for audit");
    for forbidden in [
        "static ",
        "OnceCell",
        "OnceLock",
        "RwLock",
        "Mutex",
        "RefCell",
        "Lazy",
        "lazy_static",
        "Once",
        "AtomicU",
        "AtomicI",
        "AtomicBool",
        "include_str!",
        "include_bytes!",
        "serde_json::from_str",
        "serde_json::to_string",
        "BINARY",
        "BLOB",
    ] {
        assert!(
            !bytes.contains(forbidden),
            "src/aggregate.rs must not contain {forbidden:?}"
        );
    }
}

#[test]
fn aggregate_key_serialization_never_uses_default_hasher_persisted_output() {
    // The deterministic key is an explicit snake-case string. It
    // must never be a numeric hash. We confirm by parsing the
    // aggregate's key as a string and asserting it begins with the
    // `af=` tag and contains the human-readable source id.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/happy.json");
    let fixture = parse_fixture_v1(&bytes).expect("happy must parse");
    let bundle =
        aggregate_address_family_evidence(fixture.events(), &fixture).expect("must aggregate");
    for entry in bundle.entries() {
        let key = entry.key();
        assert!(
            key.starts_with("af="),
            "key must start with explicit family tag, got {key:?}"
        );
        assert!(
            key.contains("|src="),
            "key must carry the source classification, got {key:?}"
        );
        // The key is a string; a DefaultHasher-derived fingerprint
        // would be a u64 (a bare integer), not a tagged string.
        let all_digits_or_dash = key.chars().all(|c| c.is_ascii_digit() || c == '-');
        assert!(
            !all_digits_or_dash,
            "key must not be a DefaultHasher numeric fingerprint, got {key:?}"
        );
    }
}

#[test]
fn aggregate_module_has_no_persistence_or_logging_marker() {
    // No print/log/tracing/sink/database. The aggregator is pure.
    let bytes = fs::read_to_string("src/aggregate.rs")
        .expect("src/aggregate.rs must be readable for audit");
    for forbidden in [
        "println!",
        "eprintln!",
        "print!",
        "eprint!",
        "tracing::",
        "log::",
        "env::var",
        "env::",
        "write!",
        "writeln!",
        "fs::write",
        "File::create",
        "OpenOptions",
        "serde_json::to_writer",
        "serde_json::to_vec",
        "serde_json::to_string",
    ] {
        assert!(
            !bytes.contains(forbidden),
            "src/aggregate.rs must not contain {forbidden:?}"
        );
    }
}

#[test]
fn aggregate_key_is_byte_stable_across_separate_aggregator_instances() {
    // Two independent aggregations (separate function calls, no
    // shared state) over the same input must produce byte-identical
    // keys.
    let bytes: Vec<u8> = load_canonical("tests/fixtures/happy.json");
    let fixture = parse_fixture_v1(&bytes).expect("happy must parse");
    let a = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("first aggregate must succeed");
    let b = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("second aggregate must succeed");
    for (e_a, e_b) in a.entries().zip(b.entries()) {
        assert_eq!(
            e_a.family(),
            e_b.family(),
            "family order must match across instances"
        );
        assert_eq!(e_a.key(), e_b.key(), "key must match across instances");
    }
}

#[test]
fn aggregator_does_not_introduce_serialization_outside_json_test() {
    // The aggregate module is pure; it must not call
    // serde_json::to_string (only test/audit code does that).
    // This is a structural lock on the "no sink" boundary: the
    // aggregator returns the typed bundle, and a future
    // OutputSink/projection layer handles serialization.
    let bytes = fs::read_to_string("src/aggregate.rs")
        .expect("src/aggregate.rs must be readable for audit");
    assert!(
        !bytes.contains("serde_json::to_string"),
        "aggregator must not serialize JSON itself"
    );
}
