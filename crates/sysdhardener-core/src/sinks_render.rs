//! Detailed and concise view renderers for file sinks.
//!
//! Pure formatting helpers: take an immutable projection and
//! return UTF-8 bytes for the file sink to write. No I/O, no
//! wall clock, no random, no logging, no fs. Each helper is a
//! closed mapping over the typed projection surface; non-canonical
//! inputs are not silently rewritten.

use std::fmt::Write as _;

use crate::compatibility::{SupportStatus, VerificationStatus};
use crate::fixture::{AddressFamily, CoverageQuality};
use crate::projection::{ConciseProjection, DetailedProjection};
use crate::recommendation::{
    CompatibilityRisk, ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus,
    ValidationProcedure,
};

fn family_tag(family: AddressFamily) -> String {
    match family {
        AddressFamily::Unix => "AF_UNIX".to_owned(),
        AddressFamily::Inet => "AF_INET".to_owned(),
        AddressFamily::Inet6 => "AF_INET6".to_owned(),
        AddressFamily::Netlink => "AF_NETLINK".to_owned(),
        AddressFamily::Packet => "AF_PACKET".to_owned(),
        AddressFamily::Other(tag) => format!("AF_OTHER({tag})"),
    }
}

fn render_families(families: &[AddressFamily]) -> String {
    if families.is_empty() {
        return "[]".to_owned();
    }
    let parts: Vec<String> = families.iter().map(|f| family_tag(*f)).collect();
    format!("[{}]", parts.join(", "))
}

fn render_basis(basis: &FindingBasis) -> String {
    match basis {
        FindingBasis::Absence { not_observed } => {
            format!("absence not_observed={}", render_families(not_observed))
        }
        FindingBasis::Observation { observed } => {
            format!("observation observed={}", render_families(observed))
        }
    }
}

const fn render_coverage(coverage: CoverageQuality) -> &'static str {
    match coverage {
        CoverageQuality::Complete => "complete",
        CoverageQuality::Degraded => "degraded",
        CoverageQuality::Unknown => "unknown",
    }
}

const fn render_provisional(status: ProvisionalStatus) -> &'static str {
    match status {
        ProvisionalStatus::Provisional => "provisional",
    }
}

fn render_event_loss(loss: EventLoss) -> String {
    format!(
        "seen_events={} dropped_events={}",
        loss.seen_events(),
        loss.dropped_events()
    )
}

fn render_contradiction_conditions(conditions: &[ContradictionCondition]) -> String {
    if conditions.is_empty() {
        return "[]".to_owned();
    }
    let parts: Vec<String> = conditions
        .iter()
        .map(|c| match c {
            ContradictionCondition::ObservedWithoutSuccessfulUse {
                family,
                representative_event_id,
            } => format!(
                "observed_without_successful_use family={} representative_event_id={}",
                family_tag(*family),
                representative_event_id
            ),
            ContradictionCondition::AbsentFamilyUsedLater { family } => {
                format!("absent_family_used_later family={}", family_tag(*family))
            }
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

const fn render_support(support: SupportStatus) -> &'static str {
    match support {
        SupportStatus::Supported => "supported",
        SupportStatus::Unknown => "unknown",
    }
}

const fn render_verification(verification: VerificationStatus) -> &'static str {
    match verification {
        VerificationStatus::Verified => "verified",
        VerificationStatus::Unverified => "unverified",
        VerificationStatus::Unknown => "unknown",
    }
}

const fn render_validation_procedure(procedure: ValidationProcedure) -> &'static str {
    match procedure {
        ValidationProcedure::ConfirmNoOutOfSetUse => "confirm_no_out_of_set_use",
    }
}

fn render_compatibility_risk(risk: &CompatibilityRisk) -> String {
    format!(
        "support={} verification={} source={} unverified={}",
        render_support(risk.support()),
        render_verification(risk.verification()),
        risk.source_ref().as_str(),
        risk.unverified()
    )
}

fn render_string_list(items: &[String]) -> String {
    if items.is_empty() {
        "[]".to_owned()
    } else {
        format!("[{}]", items.join(", "))
    }
}

fn push_field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "  {label}: {value}");
}

/// Render the detailed findings list to UTF-8 bytes. `pids` is the
/// optional process attribution (live-observer mode): when non-empty,
/// a line listing the observed processes is appended after the
/// header.
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling module access through crate::sinks_render requires explicit visibility"
)]
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive formatting of all typed finding labels"
)]
pub(crate) fn render_detailed(
    projection: &DetailedProjection,
    pids: &[i32],
    known_gaps: &[&str],
    cgroups: &[String],
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("Detailed findings list (provisional; not a verified audit)\n");
    out.push_str("Generated by sysdhardener analyze-fixture. Each block below is one Finding.\n");
    if !pids.is_empty() {
        let pid_list: Vec<String> = pids.iter().map(i32::to_string).collect();
        let _ = writeln!(out, "observed_processes: [{}]", pid_list.join(", "));
    }
    if !known_gaps.is_empty() {
        let _ = writeln!(out, "known_gaps: [{}]", known_gaps.join(", "));
    }
    if !cgroups.is_empty() {
        let _ = writeln!(out, "observed_cgroups: [{}]", cgroups.join(", "));
    }
    if projection.entries().is_empty() {
        out.push_str("\n(no findings)\n");
        return out.into_bytes();
    }
    for (index, entry) in projection.entries().iter().enumerate() {
        out.push('\n');
        let _ = writeln!(out, "[entry {}]", index + 1);
        push_field(&mut out, "directive", entry.directive());
        push_field(
            &mut out,
            "host_supported",
            if entry.host_supported() {
                "true"
            } else {
                "false"
            },
        );
        if let Some(val) = entry.recommended_value() {
            push_field(&mut out, "recommended_value", val);
        }
        push_field(&mut out, "basis", &render_basis(entry.basis()));
        push_field(
            &mut out,
            "observed_families",
            &render_families(entry.observed_families()),
        );
        push_field(
            &mut out,
            "recommended_families",
            &render_families(entry.recommended_families()),
        );
        push_field(
            &mut out,
            "not_observed_families",
            &render_families(entry.not_observed_families()),
        );
        let caps: Vec<&str> = entry
            .recommended_capabilities()
            .iter()
            .map(|c| c.as_str())
            .collect();
        push_field(
            &mut out,
            "recommended_capabilities",
            &format!("[{}]", caps.join(", ")),
        );
        push_field(
            &mut out,
            "provisional",
            render_provisional(entry.provisional()),
        );
        push_field(&mut out, "coverage", render_coverage(entry.coverage()));
        push_field(
            &mut out,
            "event_loss",
            &render_event_loss(*entry.event_loss()),
        );
        push_field(
            &mut out,
            "contradiction_conditions",
            &render_contradiction_conditions(entry.contradiction_conditions()),
        );
        push_field(
            &mut out,
            "compatibility_risk",
            &render_compatibility_risk(entry.compatibility_risk()),
        );
        push_field(
            &mut out,
            "validation_procedure",
            render_validation_procedure(entry.validation_procedure()),
        );
        push_field(
            &mut out,
            "source_ids",
            &render_string_list(entry.source_ids()),
        );
        push_field(
            &mut out,
            "aggregate_keys",
            &render_string_list(entry.aggregate_keys()),
        );
        push_field(
            &mut out,
            "validation_procedure_text",
            entry.validation_procedure_text(),
        );
    }
    out.into_bytes()
}

/// Render the concise projection to UTF-8 bytes.
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling module access through crate::sinks_render requires explicit visibility"
)]
pub(crate) fn render_concise(projection: &ConciseProjection) -> Vec<u8> {
    let mut out = String::new();
    for (index, line) in projection.lines().iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    out.push('\n');
    out.into_bytes()
}
