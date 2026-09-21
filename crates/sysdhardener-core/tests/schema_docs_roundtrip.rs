//! End-to-end drift test: serialize a real report from the happy
//! fixture through the actual pipeline and assert the JSON keys equal
//! the `Finding` struct fields the text parser derives from source.
//!
//! This closes the loop for the text parser in `schema_docs_fields`:
//! if the parser ever mis-reads a struct, the round-trip here disagrees
//! with real serde output and the test fails.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions on the boundary contract"
)]

use sysdhardener_core::{
    Capability, Report, RestrictAddressFamilies, aggregate_address_family_evidence,
    parse_fixture_v1, recommend_restrict_address_families, serialize_report_v1,
};

const FINDING_SRC: &str = include_str!("../src/finding.rs");
const SCHEMAS_DOC: &str = include_str!("../../../docs/schemas.md");
const HAPPY_FIXTURE: &str = include_str!("./fixtures/happy.json");

/// Field names of one struct declaration, in declaration order,
/// honoring `#[serde(rename = "...")]` on the preceding attribute.
fn struct_fields<'a>(source: &'a str, struct_name: &str) -> Vec<&'a str> {
    let start = source
        .lines()
        .position(|line| {
            line.trim_start().starts_with("pub")
                && line.contains("struct")
                && line.contains(struct_name)
                || line.trim_start().starts_with("struct") && line.contains(struct_name)
        })
        .expect("struct declaration must exist");
    let body = source
        .lines()
        .skip(start + 1)
        .take_while(|line| !line.trim_start().starts_with('}'))
        .collect::<Vec<_>>();

    let mut fields: Vec<&str> = Vec::new();
    let mut pending_rename: Option<&str> = None;
    for line in body {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(attr) = trimmed.strip_prefix("#[") {
            pending_rename = serde_rename_in(attr);
            continue;
        }
        if let Some(name) = field_name(trimmed) {
            fields.push(pending_rename.unwrap_or(name));
        }
        pending_rename = None;
    }
    fields
}

/// Extract `rename = "x"` from a serde attribute line.
fn serde_rename_in(attr: &str) -> Option<&str> {
    let needle = "rename = \"";
    let at = attr.find(needle)?;
    let rest = attr.get(at + needle.len()..)?;
    rest.split('"').next()
}

/// Extract the field name from a struct field line, allowing the
/// optional `pub(crate)` visibility prefix.
fn field_name(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let colon = rest.find(':')?;
    let name = rest.get(..colon)?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name)
}

#[test]
fn real_report_json_keys_match_parsed_source_fields() {
    let fixture = parse_fixture_v1(HAPPY_FIXTURE.as_bytes()).expect("happy fixture must parse");
    let bundle = aggregate_address_family_evidence(fixture.events(), &fixture)
        .expect("aggregation must succeed");
    let finding = recommend_restrict_address_families(
        &bundle,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
    )
    .expect("candidate must surface");
    let bytes =
        serialize_report_v1(&Report::with_findings(&[finding])).expect("report must serialize");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("report must be JSON");
    let envelope = value.as_object().expect("envelope must be an object");

    let mut envelope_keys: Vec<String> = envelope.keys().map(ToString::to_string).collect();
    envelope_keys.sort();
    assert_eq!(
        envelope_keys,
        vec![
            "findings".to_owned(),
            "host_systemd_version".to_owned(),
            "known_gaps".to_owned(),
            "observed_cgroups".to_owned(),
            "schema_version".to_owned(),
        ],
        "envelope keys must match ReportWireV1"
    );

    let finding_obj = value
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(serde_json::Value::as_object)
        .expect("one finding object");
    let mut finding_keys: Vec<String> = finding_obj.keys().map(ToString::to_string).collect();
    finding_keys.sort();
    let mut source_fields: Vec<String> = struct_fields(FINDING_SRC, "Finding")
        .into_iter()
        .map(str::to_owned)
        .collect();
    source_fields.sort();
    assert_eq!(
        finding_keys, source_fields,
        "the serialized finding must carry exactly the Finding struct fields"
    );

    let event_loss = finding_obj
        .get("event_loss")
        .and_then(serde_json::Value::as_object)
        .expect("event_loss object");
    assert_eq!(
        sorted(event_loss.keys().map(ToString::to_string).collect()),
        vec!["dropped_events".to_owned(), "seen_events".to_owned()],
        "event_loss must carry exactly the EventLoss struct fields"
    );

    let risk = finding_obj
        .get("compatibility_risk")
        .and_then(serde_json::Value::as_object)
        .expect("compatibility_risk object");
    assert_eq!(
        sorted(risk.keys().map(ToString::to_string).collect()),
        vec![
            "source_ref".to_owned(),
            "support".to_owned(),
            "verification".to_owned(),
        ],
        "compatibility_risk must carry exactly the CompatibilityRisk struct fields"
    );
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[test]
fn docs_state_version_rejection_and_uncertainty() {
    assert!(
        SCHEMAS_DOC.contains("exit code 3"),
        "fixture doc must document the unsupported-version exit code"
    );
    assert!(
        SCHEMAS_DOC.contains("schema_version"),
        "fixture doc must document the schema_version field"
    );
    assert!(
        SCHEMAS_DOC.contains("exit code 3"),
        "report doc must document the rejection exit code"
    );
    assert!(
        SCHEMAS_DOC.contains("unverified"),
        "report doc must keep compatibility uncertainty explicit"
    );
}
