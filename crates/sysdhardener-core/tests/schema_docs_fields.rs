//! Structural drift test: the `| Field (wire) |` tables in the schema
//! docs (`docs/schemas.md`)
//! must match the `serde` wire structs that define them.
//!
//! Field tables are derived from the actual struct definitions by
//! parsing the source of the wire DTOs (`fixture_wire.rs`,
//! `report.rs`, `recommendation.rs`) — including `serde` renames —
//! and compared against the first column of every `| Field (wire) |`
//! table in the docs. A real report round-trip in the sibling
//! `schema_docs_roundtrip` test proves the text parser agrees with
//! actual serde output, so a mis-parsed struct cannot stay green.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions on the boundary contract"
)]

use std::collections::BTreeSet;

const FIXTURE_WIRE_SRC: &str = include_str!("../src/fixture_wire.rs");
const REPORT_SRC: &str = include_str!("../src/report.rs");
const FINDING_SRC: &str = include_str!("../src/finding.rs");
const RECOMMENDATION_SRC: &str = include_str!("../src/recommendation.rs");
const SCHEMAS_DOC: &str = include_str!("../../../docs/schemas.md");

fn schema_section(start: &str, end: &str) -> &'static str {
    SCHEMAS_DOC
        .split_once(start)
        .and_then(|(_, body)| body.split_once(end).map(|(section, _)| section))
        .expect("combined schema document must contain both section headings")
}

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

/// Split a markdown table row into trimmed cell values. `None` for
/// non-table lines.
fn table_cells(line: &str) -> Option<Vec<&str>> {
    if !line.starts_with('|') {
        return None;
    }
    let mut parts: Vec<&str> = line.split('|').collect();
    if parts.first() == Some(&"") {
        parts.remove(0);
    }
    if parts.last() == Some(&"") {
        parts.pop();
    }
    let cells: Vec<&str> = parts.iter().map(|c| c.trim()).collect();
    if cells.is_empty() {
        return None;
    }
    Some(cells)
}

/// First-column values (backticks stripped) of every table whose
/// header's first cell is exactly `Field (wire)`.
fn wire_field_tables(md: &str) -> BTreeSet<&str> {
    let mut fields: BTreeSet<&str> = BTreeSet::new();
    let mut in_field_table = false;
    for line in md.lines() {
        let Some(cells) = table_cells(line) else {
            in_field_table = false;
            continue;
        };
        let Some(first) = cells.first() else {
            continue;
        };
        if *first == "Field (wire)" {
            in_field_table = true;
            continue;
        }
        if !in_field_table {
            continue;
        }
        if cells.iter().all(|c| c.chars().all(|c| c == '-')) {
            continue;
        }
        fields.insert(first.trim_matches('`'));
    }
    fields
}

#[test]
fn fixture_doc_field_tables_match_wire_structs() {
    let fixture_doc = schema_section("## Fixture envelope v1", "## Report envelope v1");
    let doc: BTreeSet<&str> = wire_field_tables(fixture_doc);
    let wire: BTreeSet<&str> = [
        struct_fields(FIXTURE_WIRE_SRC, "FixtureWireV1"),
        struct_fields(FIXTURE_WIRE_SRC, "EventWireV1"),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(
        doc, wire,
        "docs/schemas.md fixture field tables must match the fixture wire DTOs"
    );
}

#[test]
fn report_doc_field_tables_match_wire_structs() {
    let report_doc = schema_section("## Report envelope v1", "## Concise projection");
    let doc: BTreeSet<&str> = wire_field_tables(report_doc);
    let wire: BTreeSet<&str> = [
        struct_fields(REPORT_SRC, "ReportWireV1"),
        struct_fields(FINDING_SRC, "Finding"),
        struct_fields(RECOMMENDATION_SRC, "EventLoss"),
        struct_fields(RECOMMENDATION_SRC, "CompatibilityRisk"),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(
        doc, wire,
        "docs/schemas.md report field tables must match the report wire DTOs"
    );
}

#[test]
fn wire_parser_honors_serde_rename_for_schema_version() {
    let envelope = struct_fields(FIXTURE_WIRE_SRC, "FixtureWireV1");
    assert_eq!(
        envelope,
        vec![
            "schema_version",
            "fixture_id",
            "first_timestamp_unix_ms",
            "last_timestamp_unix_ms",
            "coverage",
            "seen_events",
            "dropped_events",
            "events",
        ],
        "the raw_schema_version field must surface as its wire name schema_version"
    );
    let event = struct_fields(FIXTURE_WIRE_SRC, "EventWireV1");
    assert_eq!(
        event,
        vec![
            "source_id",
            "event_id",
            "timestamp_unix_ms",
            "address_family",
            "outcome",
            "args",
        ]
    );
}

#[test]
fn parsed_source_fields_are_sane() {
    let finding = struct_fields(FINDING_SRC, "Finding");
    assert_eq!(
        finding.len(),
        16,
        "Finding must carry the 16 documented fields: {finding:?}"
    );
    let report = struct_fields(REPORT_SRC, "ReportWireV1");
    assert_eq!(
        report,
        vec![
            "schema_version".to_owned(),
            "findings".to_owned(),
            "host_systemd_version".to_owned(),
            "known_gaps".to_owned(),
            "observed_cgroups".to_owned()
        ]
    );
}
