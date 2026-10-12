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
use crate::fixture::{AddressFamily, CoverageQuality};
use crate::recommendation::{
    CompatibilityRisk, ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus,
    ValidationProcedure,
};

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

#[allow(
    clippy::indexing_slicing,
    reason = "equal lengths and loop bounds prove both byte indices are valid"
)]
const fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// One detailed projection entry, derived from one immutable
/// [`Finding`].
///
/// Carries every typed label consumed by the detailed text view
/// plus the small set of derived human-readable summary fields
/// (found/not-found status, validation guidance text,
/// compatibility summary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedEntry {
    directive: &'static str,
    basis: FindingBasis,
    observed_families: Vec<AddressFamily>,
    recommended_families: Vec<AddressFamily>,
    not_observed_families: Vec<AddressFamily>,
    recommended_capabilities: Vec<crate::capability::LinuxCapability>,
    host_supported: bool,
    recommended_value: Option<String>,
    provisional: ProvisionalStatus,
    coverage: CoverageQuality,
    event_loss: EventLoss,
    contradiction_conditions: Vec<ContradictionCondition>,
    compatibility_risk: CompatibilityRisk,
    validation_procedure: ValidationProcedure,
    source_ids: Vec<String>,
    aggregate_keys: Vec<String>,
}

impl DetailedEntry {
    /// Canonical systemd spelling of the directive.
    #[must_use]
    pub const fn directive(&self) -> &'static str {
        self.directive
    }
    /// Observed/not-observed basis of the finding.
    #[must_use]
    pub const fn basis(&self) -> &FindingBasis {
        &self.basis
    }
    /// Families with at least one observed event.
    #[must_use]
    pub fn observed_families(&self) -> &[AddressFamily] {
        &self.observed_families
    }
    /// Recommended allow-list (families with a representative
    /// `Success` outcome).
    #[must_use]
    pub fn recommended_families(&self) -> &[AddressFamily] {
        &self.recommended_families
    }
    /// The provisional `CapabilityBoundingSet=~CAP_X` candidate.
    #[must_use]
    pub fn recommended_capabilities(&self) -> &[crate::capability::LinuxCapability] {
        &self.recommended_capabilities
    }
    /// Whether the directive is supported by the host systemd version.
    #[must_use]
    pub const fn host_supported(&self) -> bool {
        self.host_supported
    }
    /// Known families with no observed event in the window.
    #[must_use]
    pub fn not_observed_families(&self) -> &[AddressFamily] {
        &self.not_observed_families
    }
    /// Provisional status label (always `Provisional`).
    #[must_use]
    pub const fn provisional(&self) -> ProvisionalStatus {
        self.provisional
    }
    /// Effective observation coverage.
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.coverage
    }
    /// Event-loss label.
    #[must_use]
    pub const fn event_loss(&self) -> &EventLoss {
        &self.event_loss
    }
    /// Typed contradiction conditions, in deterministic order.
    #[must_use]
    pub fn contradiction_conditions(&self) -> &[ContradictionCondition] {
        &self.contradiction_conditions
    }
    /// Compatibility-risk label.
    #[must_use]
    pub const fn compatibility_risk(&self) -> &CompatibilityRisk {
        &self.compatibility_risk
    }
    /// Validation procedure label.
    #[must_use]
    pub const fn validation_procedure(&self) -> ValidationProcedure {
        self.validation_procedure
    }
    /// Deduplicated, sorted source IDs.
    #[must_use]
    pub fn source_ids(&self) -> &[String] {
        &self.source_ids
    }
    /// Aggregate keys, in canonical family order.
    #[must_use]
    pub fn aggregate_keys(&self) -> &[String] {
        &self.aggregate_keys
    }
    /// Human-readable found/not-found status derived from the
    /// `recommended_families` length and the `CoverageQuality`.
    /// Explicit recommended value string, if any.
    #[must_use]
    pub fn recommended_value(&self) -> Option<&str> {
        self.recommended_value.as_deref()
    }

    /// Returns `None` when the entry has no observed recommendation
    /// and is fully unknown.
    #[must_use]
    pub const fn found(&self) -> Option<&'static str> {
        if self.recommended_families.is_empty()
            && self.recommended_capabilities.is_empty()
            && self.recommended_value.is_none()
        {
            match self.coverage {
                CoverageQuality::Degraded => Some("degraded"),
                CoverageQuality::Unknown | CoverageQuality::Complete => Some("not_observed"),
            }
        } else {
            Some("found")
        }
    }
    /// Validation-procedure guidance text, mapped from the typed
    /// [`ValidationProcedure`] variant. The text is a stable,
    /// minimal instruction (no prose snapshots).
    #[must_use]
    pub const fn validation_procedure_text(&self) -> &'static str {
        match self.validation_procedure {
            ValidationProcedure::ConfirmNoOutOfSetUse => {
                let directive = self.directive.as_bytes();
                if bytes_equal(directive, b"RestrictAddressFamilies") {
                    "Run the expected workload in a test unit and confirm all required socket address families are permitted."
                } else if bytes_equal(directive, b"ProtectSystem") {
                    "Run the expected workload in a test unit and confirm required system-file writes still succeed."
                } else if bytes_equal(directive, b"ProtectHome") {
                    "Run the expected workload in a test unit and confirm required home-path reads and writes still succeed."
                } else if bytes_equal(directive, b"ReadWritePaths") {
                    "Run the expected workload in a test unit and confirm writes are confined to the listed paths."
                } else if bytes_equal(directive, b"ProtectControlGroups") {
                    "Run the expected workload in a test unit and confirm it does not require writable cgroup files."
                } else if bytes_equal(directive, b"CapabilityBoundingSet")
                    || bytes_equal(directive, b"AmbientCapabilities")
                {
                    "Run the expected workload in a test unit and confirm required privileged operations still succeed."
                } else {
                    "Run the expected workload in a test unit and confirm the candidate does not prevent required behavior."
                }
            }
        }
    }
    /// Short compatibility summary including the source registry
    /// reference. The string is structural: it always carries the
    /// source ID and the unverified flag.
    #[must_use]
    pub fn compatibility_summary(&self) -> String {
        format!(
            "source={} unverified={}",
            self.compatibility_risk.source_ref().as_str(),
            self.compatibility_risk.unverified()
        )
    }
    /// Short coverage summary for the entry.
    #[must_use]
    pub fn coverage_summary(&self) -> String {
        let label: &'static str = match self.coverage {
            CoverageQuality::Complete => "complete",
            CoverageQuality::Degraded => "degraded",
            CoverageQuality::Unknown => "unknown",
        };
        format!("coverage={label}")
    }
}

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
