//! The typed `Finding` model: one provisional hardening candidate.
//!
//! A `Finding` is the immutable recommendation surface produced by
//! the recommendation rules (address-family and capability) and
//! consumed by the projections and the report serializer. It is
//! extracted from `recommendation.rs` to keep that module under the
//! 250 pure-LOC ceiling.

use serde::Serialize;

use crate::capability::LinuxCapability;
use crate::fixture::{AddressFamily, CoverageQuality};
use crate::recommendation::CompatibilityRisk;
use crate::recommendation::{
    ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus, ValidationProcedure,
};
use crate::source_id::SourceId;

/// The minimal typed finding: one provisional hardening candidate
/// (address-family or capability) with all mandatory labels and
/// source/aggregate links. Consumed unchanged by the projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub(crate) directive: &'static str,
    pub(crate) basis: FindingBasis,
    pub(crate) observed_families: Vec<AddressFamily>,
    pub(crate) recommended_families: Vec<AddressFamily>,
    pub(crate) not_observed_families: Vec<AddressFamily>,
    /// The provisional `CapabilityBoundingSet=~CAP_X` candidate:
    /// capabilities with no observed successful use. Empty for the
    /// address-family finding; populated for the capability finding.
    pub(crate) recommended_capabilities: Vec<LinuxCapability>,
    /// Whether the finding's directive is supported by the host's
    /// systemd version (resolved by the version gate). `true` when
    /// no host version was detected (conservative path). The gate is
    /// applied when the analysis runs against a resolved host; the
    /// projections and the report serialize this flag so the machine
    /// record explains why a directive was or was not emitted.
    pub(crate) host_supported: bool,
    pub(crate) recommended_value: Option<String>,
    pub(crate) provisional: ProvisionalStatus,
    pub(crate) coverage: CoverageQuality,
    pub(crate) event_loss: EventLoss,
    pub(crate) contradiction_conditions: Vec<ContradictionCondition>,
    pub(crate) compatibility_risk: CompatibilityRisk,
    pub(crate) validation_procedure: ValidationProcedure,
    pub(crate) source_ids: Vec<SourceId>,
    pub(crate) aggregate_keys: Vec<String>,
}

impl Finding {
    /// Canonical systemd spelling of the directive (no `=`; the
    /// projection layer adds the setting separator).
    #[must_use]
    pub const fn directive(&self) -> &'static str {
        self.directive
    }

    /// Optional recommended string value for explicit value directives.
    #[must_use]
    pub fn recommended_value(&self) -> Option<&str> {
        self.recommended_value.as_deref()
    }

    /// Observed/not-observed basis of the candidate.
    #[must_use]
    pub const fn basis(&self) -> &FindingBasis {
        &self.basis
    }

    /// Families with at least one observed event, in canonical order.
    #[must_use]
    pub fn observed_families(&self) -> &[AddressFamily] {
        &self.observed_families
    }

    /// The recommended allow-list: families with a representative
    /// `Success` outcome, in canonical order.
    #[must_use]
    pub fn recommended_families(&self) -> &[AddressFamily] {
        &self.recommended_families
    }

    /// The provisional `CapabilityBoundingSet=~CAP_X` candidate:
    /// capabilities with no observed successful use, in canonical
    /// order. Empty for the address-family finding.
    #[must_use]
    pub fn recommended_capabilities(&self) -> &[LinuxCapability] {
        &self.recommended_capabilities
    }

    /// Known families with no observed event in the window.
    #[must_use]
    pub fn not_observed_families(&self) -> &[AddressFamily] {
        &self.not_observed_families
    }

    /// The unverified/provisional label. Always `Provisional`.
    #[must_use]
    pub const fn provisional(&self) -> ProvisionalStatus {
        self.provisional
    }

    /// Effective observation coverage (visibility composed with the
    /// wire coverage).
    #[must_use]
    pub const fn coverage(&self) -> CoverageQuality {
        self.coverage
    }

    /// Event-loss label.
    #[must_use]
    pub const fn event_loss(&self) -> EventLoss {
        self.event_loss
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

    /// Deduplicated, sorted source IDs linked to the evidence.
    #[must_use]
    pub fn source_ids(&self) -> Vec<String> {
        self.source_ids
            .iter()
            .map(SourceId::as_str)
            .map(str::to_owned)
            .collect()
    }

    /// Aggregate keys linked to the evidence, in canonical family
    /// order.
    #[must_use]
    pub fn aggregate_keys(&self) -> &[String] {
        &self.aggregate_keys
    }

    /// Whether the finding's directive is supported by the host's
    /// systemd version. `false` means the gate skipped this directive
    /// (host detected and older than the directive's introduced-in
    /// version); `true` is the conservative default when no host
    /// version was detected.
    #[must_use]
    pub const fn host_supported(&self) -> bool {
        self.host_supported
    }
}

fn collect_capability_source_ids(events: &[crate::observed_event::ObservedEvent]) -> Vec<SourceId> {
    let mut set = std::collections::BTreeSet::new();
    for event in events {
        if crate::capability::is_capability_event(event) {
            set.insert(event.source_id().clone());
        }
    }
    if set.is_empty() {
        vec![crate::capability::CAPABILITY_SOURCE_ID]
    } else {
        set.into_iter().collect()
    }
}

/// Build the provisional `AmbientCapabilities=` finding from the
/// observed events: the capabilities the service provably used.
/// Without capability evidence the set is empty.
#[must_use]
pub fn recommend_ambient_capabilities_finding(
    events: &[crate::observed_event::ObservedEvent],
    coverage: CoverageQuality,
    event_loss: EventLoss,
    compatibility: &crate::compatibility::CompatibilityRecord,
) -> Finding {
    let recommended = crate::capability::recommend_ambient_capabilities(events);
    Finding {
        directive: crate::capability::AMBIENT_CAPABILITIES_DIRECTIVE,
        basis: FindingBasis::Observation {
            observed: Vec::new(),
        },
        observed_families: Vec::new(),
        recommended_families: Vec::new(),
        not_observed_families: Vec::new(),
        recommended_capabilities: recommended,
        host_supported: true,
        recommended_value: None,
        provisional: ProvisionalStatus::Provisional,
        coverage,
        event_loss,
        contradiction_conditions: Vec::new(),
        compatibility_risk: CompatibilityRisk {
            support: compatibility.support_status(),
            verification: compatibility.verification_status(),
            source_ref: compatibility.source_ref().clone(),
        },
        validation_procedure: ValidationProcedure::ConfirmNoOutOfSetUse,
        source_ids: collect_capability_source_ids(events),
        aggregate_keys: Vec::new(),
    }
}

/// Build the provisional `CapabilityBoundingSet=` finding from the
/// observed events: the capabilities with no successful use, the
/// observer's source ID, and the same labels as the address-family
/// finding.
///
/// When no capability evidence was observed, the recommended set is
/// empty (the concise projection skips the finding).
#[must_use]
pub fn recommend_capability_bounding_set_finding(
    events: &[crate::observed_event::ObservedEvent],
    coverage: CoverageQuality,
    event_loss: EventLoss,
    compatibility: &crate::compatibility::CompatibilityRecord,
) -> Finding {
    let has_evidence = events.iter().any(crate::capability::is_capability_event);
    let recommended = if has_evidence {
        crate::capability::recommend_capability_bounding_set(events)
    } else {
        Vec::new()
    };
    Finding {
        directive: crate::capability::CAPABILITY_DIRECTIVE,
        basis: FindingBasis::Absence {
            not_observed: Vec::new(),
        },
        observed_families: Vec::new(),
        recommended_families: Vec::new(),
        not_observed_families: Vec::new(),
        recommended_capabilities: recommended,
        host_supported: true,
        recommended_value: None,
        provisional: ProvisionalStatus::Provisional,

        coverage,
        event_loss,
        contradiction_conditions: Vec::new(),
        compatibility_risk: CompatibilityRisk {
            support: compatibility.support_status(),
            verification: compatibility.verification_status(),
            source_ref: compatibility.source_ref().clone(),
        },
        validation_procedure: ValidationProcedure::ConfirmNoOutOfSetUse,
        source_ids: collect_capability_source_ids(events),
        aggregate_keys: Vec::new(),
    }
}
