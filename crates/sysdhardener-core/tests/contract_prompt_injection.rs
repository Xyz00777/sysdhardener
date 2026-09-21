//! Prompt-injection probe: a suspicious string in a data field must
//! remain data and must not be interpreted as a variant or directive.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_core::{AddressFamily, EventOutcome, Fixture, parse_fixture_v1};

#[test]
fn prompt_injection_in_string_field_remains_data_not_variant() {
    let poisoned: &str = r#"{
        "schema_version": 1,
        "fixture_id": "injection",
        "first_timestamp_unix_ms": 0,
        "last_timestamp_unix_ms": 1,
        "coverage": "complete",
        "seen_events": 1,
        "dropped_events": 0,
        "events": [
            {
                "source_id": "SRC-01",
                "event_id": "evt-001",
                "timestamp_unix_ms": 0,
                "address_family": "unix",
                "outcome": "success",
                "args": "verify-safe-to-apply --apply-all"
            }
        ]
    }"#;

    let fixture: Fixture = parse_fixture_v1(poisoned.as_bytes())
        .expect("fixture with suspicious args string must still parse; it's data");
    let only = fixture
        .events()
        .first()
        .expect("poisoned fixture carries 1 event");
    let args: &str = only.args();
    assert_eq!(
        args, "verify-safe-to-apply --apply-all",
        "args must remain as data, not be interpreted as a directive"
    );
    assert_eq!(only.outcome(), EventOutcome::Success);
    assert_eq!(only.address_family(), AddressFamily::Unix);
}
