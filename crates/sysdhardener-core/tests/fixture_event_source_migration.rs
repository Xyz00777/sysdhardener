//! Wire-schema migration test: a fixture shaped like a legacy
//! v1 envelope (no `seen_events`/`dropped_events`, no `event_id`)
//! must be rejected at the boundary as `FixtureFieldMissing`.
//! There is no silent fallback.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the source contract"
)]

use sysdhardener_core::{Error, parse_fixture_v1};

#[test]
fn migrated_old_fixture_without_seen_dropped_is_rejected() {
    let old_shape: &str = r#"{
        "schema_version": 1,
        "fixture_id": "legacy",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "events": [
            {
                "source_id": "SRC-01",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "x"
            }
        ]
    }"#;
    let err: Error = parse_fixture_v1(old_shape.as_bytes())
        .expect_err("old fixture shape must be rejected at the boundary");
    assert!(
        matches!(err, Error::FixtureFieldMissing { .. }),
        "expected Error::FixtureFieldMissing for missing new fields, got {err:?}"
    );
}
