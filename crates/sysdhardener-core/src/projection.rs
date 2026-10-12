//! Canonical detailed and concise projections of the immutable
//! `Finding` collection.
//!
//! The two views are derived from the same immutable
//! `&[Finding]` slice: the detailed view exposes every typed label
//! (basis, observed/recommended/not-observed families, provisional
//! status, observation coverage, event loss, contradiction
//! conditions, compatibility risk, validation procedure, source and
//! aggregate links) and the concise view is a single warning line
//! followed by exactly one setting per finding, with no
//! per-setting comments, trace IDs, or companion warning. The
//! projection layer is **pure**: no I/O, no wall clock, no random,
//! no logging, no sink, no re-run of the recommendation function.
//!
//! The single exported constant is [`CONCISE_WARNING`]; it is the
//! first line of every successful concise projection and appears
//! nowhere else in the produced view. The invariant that every
//! concise setting maps to exactly one finding is enforced by
//! [`project_concise`], which returns
//! [`Error::UnlinkedConciseSetting`] rather than silently dropping
//! or fabricating a setting.

use crate::error::Error;
use crate::finding::Finding;
use crate::fixture::AddressFamily;

/// The single, file-level warning line that opens every successful
/// concise projection. It states that the settings are
/// provisional/unverified and require validation before use.
///
/// The string is the contract; consumers parse the first line of
/// the concise projection and assert it equals this constant. The
/// constant is defined here exactly once and re-exported by the
/// crate root exactly once (see the
/// `detailed_concise_projection_audit` integration test).
pub const CONCISE_WARNING: &str =
    "# WARNING: settings below are provisional and unverified; validate before use.";

pub use crate::detailed_entry::DetailedEntry;

/// The detailed projection: a vector of [`DetailedEntry`] values,
/// one per immutable [`Finding`], in input order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetailedProjection {
    entries: Vec<DetailedEntry>,
}

impl DetailedProjection {
    /// Borrow the detailed entries in input order.
    #[must_use]
    pub fn entries(&self) -> &[DetailedEntry] {
        &self.entries
    }
}

/// The concise projection: a vector of string lines.
///
/// The first line is always [`CONCISE_WARNING`]; the remaining lines
/// are the recommended settings, one per finding, with no per-setting
/// comments, trace IDs, or companion warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConciseProjection {
    lines: Vec<String>,
}

impl ConciseProjection {
    /// Construct an empty concise projection containing only [`CONCISE_WARNING`].
    #[must_use]
    pub fn empty() -> Self {
        Self {
            lines: vec![CONCISE_WARNING.to_owned()],
        }
    }

    /// Borrow the concise projection lines in order.
    /// Line 0 is [`CONCISE_WARNING`]; the remaining lines are the
    /// recommended settings.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// Project the detailed findings list into the detailed view.
///
/// The detailed projection is total: an empty input yields an
/// empty [`DetailedProjection`]. The projection does not re-run
/// the recommendation function and is otherwise a pure mapping
/// from [`Finding`] to [`DetailedEntry`].
#[must_use]
pub fn project_detailed(findings: &[Finding]) -> DetailedProjection {
    let entries: Vec<DetailedEntry> = findings.iter().map(project_entry).collect();
    DetailedProjection { entries }
}

fn project_entry(finding: &Finding) -> DetailedEntry {
    DetailedEntry {
        directive: finding.directive(),
        basis: finding.basis().clone(),
        observed_families: finding.observed_families().to_vec(),
        recommended_families: finding.recommended_families().to_vec(),
        not_observed_families: finding.not_observed_families().to_vec(),
        recommended_capabilities: finding.recommended_capabilities().to_vec(),
        host_supported: finding.host_supported(),
        recommended_value: finding.recommended_value().map(ToOwned::to_owned),
        provisional: finding.provisional(),
        coverage: finding.coverage(),
        event_loss: finding.event_loss(),
        contradiction_conditions: finding.contradiction_conditions().to_vec(),
        compatibility_risk: finding.compatibility_risk().clone(),
        validation_procedure: finding.validation_procedure(),
        source_ids: finding.source_ids(),
        aggregate_keys: finding.aggregate_keys().to_vec(),
    }
}

/// Project the concise findings list into the concise view.
///
/// The first line is always [`CONCISE_WARNING`]. The remaining
/// lines are the recommended settings, one per finding, in
/// canonical family order. A finding whose directive is not
/// supported by the host's systemd version (when one was detected)
/// is skipped, not errored.
///
/// # Errors
/// Returns [`Error::UnlinkedConciseSetting`] when the projection
/// would otherwise emit a concise setting that does not map to a
/// finding's `recommended_families`. The `finding_index` field
/// is `Some(index)` for an offending finding (empty recommended
/// slice) and `None` for an empty input.
///
/// Findings whose `host_supported` flag is `false` (the version gate
/// skipped them because the host systemd is older than the
/// directive's introduced-in version) are omitted from the settings.
pub fn project_concise(findings: &[Finding]) -> Result<ConciseProjection, Error> {
    if findings.is_empty() {
        return Err(Error::UnlinkedConciseSetting {
            recommended: Vec::new(),
            finding_index: None,
        });
    }
    let mut lines: Vec<String> = Vec::with_capacity(findings.len() + 1);
    lines.push(CONCISE_WARNING.to_owned());
    for (index, finding) in findings.iter().enumerate() {
        if !finding.host_supported() {
            continue;
        }
        if let Some(val) = finding.recommended_value() {
            lines.push(format!("{}={val}", finding.directive()));
            continue;
        }
        if finding.directive() == crate::capability::CAPABILITY_DIRECTIVE {
            // CapabilityBoundingSet=~CAP_X: the recommended set is the
            // capabilities to drop. An empty set means "nothing to
            // drop" — the finding is skipped, not an error.
            let caps: &[crate::capability::LinuxCapability] = finding.recommended_capabilities();
            if caps.is_empty() {
                continue;
            }
            let tags: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
            lines.push(format!("{}=~{}", finding.directive(), tags.join(" ")));
            continue;
        }
        if finding.directive() == crate::capability::AMBIENT_CAPABILITIES_DIRECTIVE {
            // AmbientCapabilities=CAP_X: the capabilities to re-grant.
            // An empty set means "nothing to grant" — skipped.
            let caps: &[crate::capability::LinuxCapability] = finding.recommended_capabilities();
            if caps.is_empty() {
                continue;
            }
            let tags: Vec<&str> = caps.iter().map(|c| c.as_str()).collect();
            lines.push(format!("{}={}", finding.directive(), tags.join(" ")));
            continue;
        }
        let families: &[AddressFamily] = finding.recommended_families();
        if families.is_empty() {
            return Err(Error::UnlinkedConciseSetting {
                recommended: Vec::new(),
                finding_index: Some(index),
            });
        }
        lines.push(build_setting_line(finding.directive(), families));
    }
    Ok(ConciseProjection { lines })
}

/// Build a single concise setting line for the given directive and
/// family slice. The setting is rendered generically from the
/// recommended allow-list, so any non-empty combination the
/// recommendation produces (including combinations the fixture
/// slice never exercised, e.g. `unix+inet+inet6+netlink` from a
/// live observation) is representable.
fn build_setting_line(directive: &'static str, families: &[AddressFamily]) -> String {
    let tags: Vec<&str> = families.iter().map(|f| family_setting_tag(*f)).collect();
    format!("{directive}={}", tags.join(" "))
}

/// The systemd spelling of one address family in a
/// `RestrictAddressFamilies=` setting.
const fn family_setting_tag(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Unix => "AF_UNIX",
        AddressFamily::Inet => "AF_INET",
        AddressFamily::Inet6 => "AF_INET6",
        AddressFamily::Netlink => "AF_NETLINK",
        AddressFamily::Packet => "AF_PACKET",
        AddressFamily::Other(tag) => tag,
    }
}
