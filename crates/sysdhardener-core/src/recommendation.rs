//! The single provisional `RestrictAddressFamilies=` recommendation.
//!
//! Exactly one concrete
//! recommendation function that consumes the recommendation-local
//! aggregate bundle, the visibility classification, and the
//! compatibility record, and always surfaces the absence-derived
//! candidate with all mandatory labels (not observed,
//! unverified/provisional, observation coverage, event loss,
//! contradiction conditions, compatibility risk, validation
//! procedure). The candidate is **recommendation-only**: it carries no
//! hardening action, and the typed labels make verified/safe/complete
//! claims unrepresentable. There is no generic rule mechanism and no
//! second directive in this module.
//!
//! This module is **pure**: no I/O, no wall clock, no random, no
//! global state, no logging, no projection, no sink. It owns the
//! minimal typed `Finding` model shared with the projections.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::aggregate::{AddressFamilyAggregate, AddressFamilyBundle};
use crate::compatibility::{CompatibilityRecord, validate_compatibility};
use crate::error::Error;
use crate::finding::Finding;
use crate::fixture::{AddressFamily, CoverageQuality, EventOutcome};
use crate::ports::{Capability, combine_visibility};
use crate::source_id::SourceId;

/// The closed set of concrete families the tool models. `Other`
/// variants are open-ended and can never be enumerated, so absence is
/// only meaningful against this list.
#[allow(
    clippy::redundant_pub_crate,
    reason = "crate-visible for the analysis seam"
)]
pub(crate) const KNOWN_FAMILIES: [AddressFamily; 5] = [
    AddressFamily::Unix,
    AddressFamily::Inet,
    AddressFamily::Inet6,
    AddressFamily::Netlink,
    AddressFamily::Packet,
];

/// Provisional status of the candidate. The single variant is
/// deliberate: a candidate can never be marked verified or safe, so
/// those claims are unrepresentable in the type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProvisionalStatus {
    /// The candidate is provisional: absence is not proof of non-use.
    Provisional,
}

/// Observed/not-observed basis of the finding (ddd-model Section 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FindingBasis {
    /// At least one known family was not observed in the window; the
    /// candidate is absence-derived.
    Absence {
        /// Families with no observed event in the window.
        not_observed: Vec<AddressFamily>,
    },
    /// Every known family was observed; the candidate is fully
    /// observation-derived.
    Observation {
        /// Families with at least one observed event.
        observed: Vec<AddressFamily>,
    },
}

/// A typed condition under which the candidate is contradicted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContradictionCondition {
    /// A family was observed with a representative outcome of `Error`.
    /// Failed exploratory syscalls are not evidence of use; successful
    /// use of this family later contradicts the candidate.
    ObservedWithoutSuccessfulUse {
        /// The family observed without successful use.
        family: AddressFamily,
        /// Link to the representative event that carried the
        /// error outcome.
        representative_event_id: String,
    },
    /// A known family had no observed event. Observing successful use
    /// of it later contradicts the candidate.
    AbsentFamilyUsedLater {
        /// The family that was absent from the window.
        family: AddressFamily,
    },
}

/// Event-loss label: how much of the window was seen and dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventLoss {
    pub(crate) seen_events: u32,
    pub(crate) dropped_events: u32,
}

impl EventLoss {
    /// Number of events the observer captured in the window.
    #[must_use]
    pub const fn seen_events(&self) -> u32 {
        self.seen_events
    }

    /// Number of events the observer reports were dropped.
    #[must_use]
    pub const fn dropped_events(&self) -> u32 {
        self.dropped_events
    }

    /// Whether any event loss was declared.
    #[must_use]
    pub const fn has_loss(&self) -> bool {
        self.dropped_events > 0
    }
}

/// Compatibility-risk label derived from the typed compatibility
/// record. Carries the record's typed facts so the risk is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityRisk {
    pub(crate) support: crate::compatibility::SupportStatus,
    pub(crate) verification: crate::compatibility::VerificationStatus,
    pub(crate) source_ref: SourceId,
}

impl CompatibilityRisk {
    /// Support-status classification from the record.
    #[must_use]
    pub const fn support(&self) -> crate::compatibility::SupportStatus {
        self.support
    }

    /// Verification-status classification from the record.
    #[must_use]
    pub const fn verification(&self) -> crate::compatibility::VerificationStatus {
        self.verification
    }

    /// Registry source supplying the compatibility evidence.
    #[must_use]
    pub const fn source_ref(&self) -> &SourceId {
        &self.source_ref
    }

    /// Whether the risk is unverified: either support is not claimed or
    /// the record is not verified. `false` is reachable only when the
    /// record claims `Supported` *and* `Verified`.
    #[must_use]
    pub const fn unverified(&self) -> bool {
        !matches!(self.support, crate::compatibility::SupportStatus::Supported)
            || !matches!(
                self.verification,
                crate::compatibility::VerificationStatus::Verified
            )
    }
}

/// The validation procedure a maintainer follows before treating the
/// candidate as validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationProcedure {
    /// Apply the candidate to a test unit, run the expected workload,
    /// and confirm no family outside the recommended allow-list is used
    /// before treating the candidate as validated.
    ConfirmNoOutOfSetUse,
}

/// Produce the single provisional `RestrictAddressFamilies=` candidate
/// from recommendation-local evidence.
///
/// Always surfaces the absence-derived candidate: never
/// hidden under low coverage, dropped events, degraded visibility, or
/// unknown compatibility. The recommended allow-list is the set of
/// families with a representative `Success` outcome; every family
/// observed without successful use and every known-but-unobserved
/// family becomes a typed contradiction condition. The result is
/// recommendation-only and carries every mandatory label.
///
/// # Errors
/// Returns [`Error::CompatibilityUnknownSource`] when the record (or a
/// `VersionFact::Verified` evidence source) references a `SourceId`
/// outside the compiled registry allowlist.
pub fn recommend_restrict_address_families(
    bundle: &AddressFamilyBundle,
    visibility: Capability,
    compatibility: &CompatibilityRecord,
) -> Result<Finding, Error> {
    validate_compatibility(compatibility)?;

    let coverage: CoverageQuality = combine_visibility(visibility, bundle.coverage());
    // Only the closed set of known families is recommendation
    // evidence. `Other` families (e.g. the observer's
    // `Other("capability")` events) are not `RestrictAddressFamilies=`
    // candidates and must never enter the allow-list.
    let observed: Vec<AddressFamily> = bundle
        .entries()
        .map(AddressFamilyAggregate::family)
        .filter(|family| KNOWN_FAMILIES.contains(family))
        .collect();
    let recommended: Vec<AddressFamily> = bundle
        .entries()
        // A family the service *attempts* is a family it needs, even
        // when the specific call failed or its outcome is unverified
        // (e.g. the eBPF observer, which cannot see syscall returns):
        // denying it would break the service with EAFNOSUPPORT. Only a
        // representative `Error` outcome with no successful/unknown
        // sibling is excluded (a family the service provably cannot
        // use).
        .filter(|entry| entry.representative_outcome() != EventOutcome::Error)
        .map(AddressFamilyAggregate::family)
        .filter(|family| observed.contains(family))
        .collect();
    let not_observed: Vec<AddressFamily> = KNOWN_FAMILIES
        .iter()
        .copied()
        .filter(|family| !observed.contains(family))
        .collect();

    let basis: FindingBasis = if not_observed.is_empty() {
        FindingBasis::Observation {
            observed: observed.clone(),
        }
    } else {
        FindingBasis::Absence {
            not_observed: not_observed.clone(),
        }
    };

    let mut contradiction_conditions: Vec<ContradictionCondition> = bundle
        .entries()
        .filter(|entry| KNOWN_FAMILIES.contains(&entry.family()))
        .filter(|entry| entry.representative_outcome() == EventOutcome::Error)
        .map(
            |entry| ContradictionCondition::ObservedWithoutSuccessfulUse {
                family: entry.family(),
                representative_event_id: entry.representative_event_id().to_owned(),
            },
        )
        .collect();
    contradiction_conditions.extend(
        not_observed
            .iter()
            .map(|family| ContradictionCondition::AbsentFamilyUsedLater { family: *family }),
    );

    let aggregate_keys: Vec<String> = bundle
        .entries()
        .filter(|entry| KNOWN_FAMILIES.contains(&entry.family()))
        .map(|entry| entry.key().to_owned())
        .collect();
    let mut source_ids: BTreeSet<SourceId> = BTreeSet::new();
    for id in bundle
        .entries()
        .filter(|entry| KNOWN_FAMILIES.contains(&entry.family()))
        .flat_map(AddressFamilyAggregate::source_ids)
    {
        source_ids.insert(SourceId::parse(&id)?);
    }

    let compatibility_risk = CompatibilityRisk {
        support: compatibility.support_status(),
        verification: compatibility.verification_status(),
        source_ref: compatibility.source_ref().clone(),
    };

    Ok(Finding {
        directive: "RestrictAddressFamilies",
        basis,
        observed_families: observed,
        recommended_families: recommended,
        not_observed_families: not_observed,
        recommended_capabilities: Vec::new(),
        host_supported: true,
        recommended_value: None,
        provisional: ProvisionalStatus::Provisional,

        coverage,
        event_loss: EventLoss {
            seen_events: bundle.seen_events(),
            dropped_events: bundle.dropped_events(),
        },
        contradiction_conditions,
        compatibility_risk,
        validation_procedure: ValidationProcedure::ConfirmNoOutOfSetUse,
        source_ids: source_ids.into_iter().collect(),
        aggregate_keys,
    })
}
