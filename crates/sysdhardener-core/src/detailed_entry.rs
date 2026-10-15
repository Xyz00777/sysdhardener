//! Detailed projection entry type.

use crate::fixture::{AddressFamily, CoverageQuality};
use crate::recommendation::{
    CompatibilityRisk, ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus,
    ValidationProcedure,
};

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
/// [`crate::Finding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedEntry {
    pub(crate) directive: &'static str,
    pub(crate) basis: FindingBasis,
    pub(crate) observed_families: Vec<AddressFamily>,
    pub(crate) recommended_families: Vec<AddressFamily>,
    pub(crate) not_observed_families: Vec<AddressFamily>,
    pub(crate) recommended_capabilities: Vec<crate::capability::LinuxCapability>,
    pub(crate) host_supported: bool,
    pub(crate) recommended_value: Option<String>,
    pub(crate) provisional: ProvisionalStatus,
    pub(crate) coverage: CoverageQuality,
    pub(crate) event_loss: EventLoss,
    pub(crate) contradiction_conditions: Vec<ContradictionCondition>,
    pub(crate) compatibility_risk: CompatibilityRisk,
    pub(crate) validation_procedure: ValidationProcedure,
    pub(crate) source_ids: Vec<String>,
    pub(crate) aggregate_keys: Vec<String>,
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
    /// Recommended allow-list (families with a representative `Success` outcome).
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
    /// Explicit recommended value string, if any.
    #[must_use]
    pub fn recommended_value(&self) -> Option<&str> {
        self.recommended_value.as_deref()
    }
    /// Returns `None` when the entry has no observed recommendation and is fully unknown.
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
    /// Validation-procedure guidance text.
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
    /// Short compatibility summary including the source registry reference.
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
