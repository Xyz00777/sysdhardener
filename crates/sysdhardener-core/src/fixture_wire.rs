//! Private wire DTOs and `serde_json` error mapper for the fixture
//! envelope. Kept separate from the public types in [`crate::fixture`]
//! so the wire shape can evolve without leaking into the typed
//! interior.

// `pub(crate)` items inside a private module trip
// `redundant_pub_crate`; the items are crate-visible by
// construction and the explicit marker is intentional for the
// wire DTO module's contract.
#![allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) markers document the wire-DTO module's crate-local intent"
)]

use serde::Deserialize;

use crate::error::Error;

#[derive(Debug, Deserialize)]
pub(crate) struct FixtureWireV1 {
    #[serde(rename = "schema_version")]
    pub(crate) raw_schema_version: u32,
    pub(crate) fixture_id: String,
    pub(crate) first_timestamp_unix_ms: i64,
    pub(crate) last_timestamp_unix_ms: i64,
    pub(crate) coverage: String,
    pub(crate) seen_events: u32,
    pub(crate) dropped_events: u32,
    pub(crate) events: Vec<EventWireV1>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EventWireV1 {
    pub(crate) source_id: String,
    pub(crate) event_id: String,
    pub(crate) timestamp_unix_ms: i64,
    pub(crate) address_family: String,
    pub(crate) outcome: String,
    pub(crate) args: String,
}

/// Map a `serde_json` error to a typed boundary [`Error`].
pub(crate) fn map_serde_error(e: &serde_json::Error) -> Error {
    if e.is_syntax() || e.is_eof() || e.is_io() {
        return Error::JsonSyntax {
            line: e.line(),
            column: e.column(),
        };
    }
    if e.is_data() {
        let msg = format!("{e}");
        if let Some(field) = extract_missing_field(&msg) {
            return Error::FixtureFieldMissing { field };
        }
    }
    Error::JsonShape(format!("{e}"))
}

fn extract_missing_field(display: &str) -> Option<&'static str> {
    let rest = display.strip_prefix("missing field `")?;
    let name = rest.split('`').next()?;
    match name {
        "schema_version" => Some("schema_version"),
        "fixture_id" => Some("fixture_id"),
        "first_timestamp_unix_ms" => Some("first_timestamp_unix_ms"),
        "last_timestamp_unix_ms" => Some("last_timestamp_unix_ms"),
        "coverage" => Some("coverage"),
        "seen_events" => Some("seen_events"),
        "dropped_events" => Some("dropped_events"),
        "events" => Some("events"),
        "source_id" => Some("source_id"),
        "event_id" => Some("event_id"),
        "timestamp_unix_ms" => Some("timestamp_unix_ms"),
        "address_family" => Some("address_family"),
        "outcome" => Some("outcome"),
        "args" => Some("args"),
        _ => None,
    }
}
