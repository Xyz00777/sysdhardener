//! Test-only seams for the projection layer.
//!
//! Compiled only under the `testing` feature so production builds
//! never expose an assembly path that bypasses the canonical
//! [`crate::recommendation::recommend_restrict_address_families`]
//! pipeline. The seams let integration tests construct a
//! [`Finding`] with arbitrary `recommended_families` (including
//! non-canonical slices the canonical pipeline never produces) and
//! a [`CompatibilityRisk`] from raw typed facts, so the
//! projection rejection invariant can be locked end to end.

use crate::compatibility::{SupportStatus, VerificationStatus};
use crate::finding::Finding;
use crate::fixture::{AddressFamily, CoverageQuality};
use crate::recommendation::{
    CompatibilityRisk, ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus,
    ValidationProcedure,
};
use crate::source_id::SourceId;

/// Build a [`Finding`] with arbitrary `recommended_families` (and
/// the rest of the typed label set defaulted to a single
/// `Provisional`/`Complete` shape).
///
/// Tests use the seam to drive [`crate::projection::project_concise`]
/// with non-canonical recommended slices that the canonical
/// pipeline cannot produce, locking the rejection invariant end
/// to end.
#[cfg(feature = "testing")]
#[allow(
    clippy::too_many_arguments,
    reason = "test-only seam exercises every label field independently"
)]
pub const fn finding_synthetic_for_test(
    directive: &'static str,
    basis: FindingBasis,
    observed_families: Vec<AddressFamily>,
    recommended_families: Vec<AddressFamily>,
    not_observed_families: Vec<AddressFamily>,
    coverage: CoverageQuality,
    contradiction_conditions: Vec<ContradictionCondition>,
    compatibility_risk: CompatibilityRisk,
    source_ids: Vec<SourceId>,
    aggregate_keys: Vec<String>,
) -> Finding {
    Finding {
        directive,
        basis,
        observed_families,
        recommended_families,
        not_observed_families,
        recommended_capabilities: Vec::new(),
        host_supported: true,
        recommended_value: None,
        provisional: ProvisionalStatus::Provisional,

        coverage,
        event_loss: EventLoss {
            seen_events: 0,
            dropped_events: 0,
        },
        contradiction_conditions,
        compatibility_risk,
        validation_procedure: ValidationProcedure::ConfirmNoOutOfSetUse,
        source_ids,
        aggregate_keys,
    }
}

/// Build a [`CompatibilityRisk`] from its three typed facts.
///
/// Compiled only under the `testing` feature so production builds
/// never expose an assembly path that bypasses the
/// compatibility-record validation.
#[cfg(feature = "testing")]
#[must_use]
pub const fn compatibility_risk_synthetic_for_test(
    support: SupportStatus,
    verification: VerificationStatus,
    source_ref: SourceId,
) -> CompatibilityRisk {
    CompatibilityRisk {
        support,
        verification,
        source_ref,
    }
}
