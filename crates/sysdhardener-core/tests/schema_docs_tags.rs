//! Structural drift test: the enum tag tables in the schema docs
//! (`docs/schemas.md`) must
//! match the actual `serde` JSON tags of the public enums.
//!
//! Unlike the field tables (verified in `schema_docs_fields`), the
//! tag tables are verified by serializing the enums through
//! `serde_json` and comparing the resulting wire tags — so the docs
//! cannot drift from serde's tag choice without this test failing.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap for direct assertions on the boundary contract"
)]

use serde::Serialize;
use sysdhardener_core::{
    AddressFamily, ContradictionCondition, CoverageQuality, EventOutcome, FindingBasis,
    ProvisionalStatus, SupportStatus, ValidationProcedure, VerificationStatus,
};

const SCHEMAS_DOC: &str = include_str!("../../../docs/schemas.md");

fn schema_section(start: &str, end: &str) -> &'static str {
    SCHEMAS_DOC
        .split_once(start)
        .and_then(|(_, body)| body.split_once(end).map(|(section, _)| section))
        .expect("combined schema document must contain both section headings")
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

/// First-column value (backticks stripped) and comma-split tag list of
/// every row in the `| Field | Wire tags (JSON string) |` table.
fn tag_table(md: &str) -> Vec<(&str, Vec<&str>)> {
    let mut rows: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut in_tag_table = false;
    for line in md.lines() {
        let Some(cells) = table_cells(line) else {
            in_tag_table = false;
            continue;
        };
        if cells.first().is_some_and(|c| *c == "Field")
            && cells
                .get(1)
                .is_some_and(|c| *c == "Wire tags (JSON string)")
        {
            in_tag_table = true;
            continue;
        }
        if !in_tag_table {
            continue;
        }
        if cells.iter().all(|c| c.chars().all(|c| c == '-')) {
            continue;
        }
        let (Some(field), Some(tags)) = (cells.first(), cells.get(1)) else {
            continue;
        };
        let tags: Vec<&str> = tags
            .split(',')
            .map(|t| t.trim().trim_matches('`'))
            .collect();
        rows.push((field.trim_matches('`'), tags));
    }
    rows
}

/// Serialize unit enum variants to their JSON string tags.
fn unit_tags<T: Serialize>(variants: &[T]) -> Vec<String> {
    variants
        .iter()
        .map(|variant| {
            serde_json::to_value(variant)
                .expect("enum must serialize")
                .as_str()
                .expect("unit variant must serialize as a JSON string")
                .to_owned()
        })
        .collect()
}

/// Serialize internally tagged enum variants and return their `kind`.
fn kind_tags<T: Serialize>(variants: &[T]) -> Vec<String> {
    variants
        .iter()
        .map(|variant| {
            serde_json::to_value(variant)
                .expect("enum must serialize")
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .expect("internally tagged enum must carry a kind string")
                .to_owned()
        })
        .collect()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

#[test]
fn fixture_doc_tag_table_matches_serde_tags() {
    let fixture_doc = schema_section("## Fixture envelope v1", "## Report envelope v1");
    let rows: Vec<(&str, Vec<&str>)> = tag_table(fixture_doc);
    assert_eq!(
        rows.len(),
        3,
        "fixture doc must table exactly three tag fields"
    );
    for (field, tags) in rows {
        let expected: Vec<String> = match field {
            "coverage" => unit_tags(&[
                CoverageQuality::Complete,
                CoverageQuality::Degraded,
                CoverageQuality::Unknown,
            ]),
            "address_family" => unit_tags(&[
                AddressFamily::Unix,
                AddressFamily::Inet,
                AddressFamily::Inet6,
                AddressFamily::Netlink,
                AddressFamily::Packet,
            ]),
            "outcome" => unit_tags(&[
                EventOutcome::Success,
                EventOutcome::Error,
                EventOutcome::Interrupted,
                EventOutcome::Unknown,
            ]),
            _ => panic!("unexpected fixture tag-table field {field:?}"),
        };
        assert_eq!(
            sorted(tags.into_iter().map(str::to_owned).collect()),
            sorted(expected)
        );
    }
}

#[test]
fn report_doc_tag_table_matches_serde_tags() {
    let report_doc = schema_section("## Report envelope v1", "## Concise projection");
    let rows: Vec<(&str, Vec<&str>)> = tag_table(report_doc);
    assert_eq!(
        rows.len(),
        8,
        "report doc must table exactly eight tag fields"
    );
    for (field, tags) in rows {
        let expected: Vec<String> = match field {
            "provisional" => unit_tags(&[ProvisionalStatus::Provisional]),
            "validation_procedure" => unit_tags(&[ValidationProcedure::ConfirmNoOutOfSetUse]),
            "coverage" => unit_tags(&[
                CoverageQuality::Complete,
                CoverageQuality::Degraded,
                CoverageQuality::Unknown,
            ]),
            "support" => unit_tags(&[SupportStatus::Supported, SupportStatus::Unknown]),
            "verification" => unit_tags(&[
                VerificationStatus::Verified,
                VerificationStatus::Unverified,
                VerificationStatus::Unknown,
            ]),
            "basis.kind" => kind_tags(&[
                FindingBasis::Absence {
                    not_observed: Vec::new(),
                },
                FindingBasis::Observation {
                    observed: Vec::new(),
                },
            ]),
            "contradiction_conditions[].kind" => kind_tags(&[
                ContradictionCondition::ObservedWithoutSuccessfulUse {
                    family: AddressFamily::Inet,
                    representative_event_id: "evt".to_owned(),
                },
                ContradictionCondition::AbsentFamilyUsedLater {
                    family: AddressFamily::Unix,
                },
            ]),
            field if field.contains("elements") => unit_tags(&[
                AddressFamily::Unix,
                AddressFamily::Inet,
                AddressFamily::Inet6,
                AddressFamily::Netlink,
                AddressFamily::Packet,
            ]),
            _ => panic!("unexpected report tag-table field {field:?}"),
        };
        assert_eq!(
            sorted(tags.into_iter().map(str::to_owned).collect()),
            sorted(expected)
        );
    }
}
