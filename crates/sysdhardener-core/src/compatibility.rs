//! Minimal-plus-exceptions compatibility provenance record.
//!
//! Each compatibility record carries the
//! required fields `directive`, `support_status`, `source_ref`,
//! `verification_status`, and `introduced_in`, plus conditional
//! exception fields (`changed_in`, `deprecated_in`, `removed_in`,
//! `superseded_by`, `kernel_dependency`) only when applicable. The
//! `source_ref` always points to a deduplicated source registry ID
//! from `docs/research.md`; the compiled allowlist
//! lives in this module so the runtime never reads the registry file
//! (test-only audit parses it; runtime uses the compile-time slice).
//!
//! Unknown or unverified facts are represented as typed variants
//! (`VersionFact::Unknown`, `VerificationStatus::Unverified`,
//! `SupportStatus::Unknown`); no baseline, kernel, or systemd
//! version literal is fabricated anywhere in this crate.

use serde::Serialize;

use crate::error::Error;
use crate::source_id::SourceId;

/// Typed support-status classification.
///
/// `Unknown` means the host baseline is not yet verified;
/// `Supported` requires a verified source confirming the directive
/// is implemented on the host's systemd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SupportStatus {
    /// The directive is supported on the host's systemd version.
    /// Requires `VerificationStatus::Verified` to be a meaningful
    /// claim; `CompatibilityRisk::unverified` enforces the cross-field invariant.
    Supported,
    /// The directive's support on the host is not yet determined.
    Unknown,
}

/// Typed verification-status classification for the compatibility
/// record as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationStatus {
    /// The record has been verified against a known registry entry.
    Verified,
    /// The record has been gathered but not verified.
    Unverified,
    /// The record's verification status is not yet determined.
    Unknown,
}

/// A version-sensitive compatibility fact.
///
/// `Verified` is the only variant that asserts a real claim, and it
/// structurally carries the `SourceId` of the registry entry that
/// supplies the evidence. The validator rejects any `Verified` whose
/// `source_ref` is not in the compiled registry allowlist; a
/// `Verified` without an evidence source cannot be constructed at
/// all (the variant has no fields-less arm).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum VersionFact {
    /// The exception field is not applicable for this directive.
    Absent,
    /// The version-sensitive fact has not been gathered yet.
    Unknown,
    /// The version-sensitive fact has been gathered but not verified.
    Unverified,
    /// The version-sensitive fact has been verified against the
    /// registry entry named by `source_ref`. The validator requires
    /// `source_ref` to be in the compiled allowlist.
    Verified {
        /// Registry `SourceId` supplying the version-sensitive
        /// evidence; the validator enforces allowlist membership.
        source_ref: SourceId,
    },
}

/// A minimal-plus-exceptions compatibility provenance record.
///
/// The constructor is `new_unchecked` — every caller-side boundary
/// (a future recommendation-rule seam, an audit test, the canonical
/// `RestrictAddressFamilies` constant) must run the record through
/// [`validate_compatibility`] before treating it as evidence. The
/// canonical record is exposed via [`RestrictAddressFamilies::record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityRecord {
    directive: &'static str,
    support_status: SupportStatus,
    source_ref: SourceId,
    verification_status: VerificationStatus,
    introduced_in: VersionFact,
    changed_in: Option<VersionFact>,
    deprecated_in: Option<VersionFact>,
    removed_in: Option<VersionFact>,
    superseded_by: Option<&'static str>,
    kernel_dependency: Option<VersionFact>,
}

impl CompatibilityRecord {
    /// Construct a record without running validation. Public so the
    /// test suite and the canonical `RestrictAddressFamilies` seam
    /// can build records that are then validated; production code
    /// paths that produce a record must call
    /// [`validate_compatibility`] before treating it as evidence.
    #[allow(clippy::too_many_arguments, reason = "record shape is fixed by design")]
    pub const fn new_unchecked(
        directive: &'static str,
        support_status: SupportStatus,
        source_ref: SourceId,
        verification_status: VerificationStatus,
        introduced_in: VersionFact,
        changed_in: Option<VersionFact>,
        deprecated_in: Option<VersionFact>,
        removed_in: Option<VersionFact>,
        superseded_by: Option<&'static str>,
        kernel_dependency: Option<VersionFact>,
    ) -> Self {
        Self {
            directive,
            support_status,
            source_ref,
            verification_status,
            introduced_in,
            changed_in,
            deprecated_in,
            removed_in,
            superseded_by,
            kernel_dependency,
        }
    }

    /// Directive name (the canonical systemd spelling).
    #[must_use]
    pub const fn directive(&self) -> &'static str {
        self.directive
    }

    /// Support-status classification.
    #[must_use]
    pub const fn support_status(&self) -> SupportStatus {
        self.support_status
    }

    /// Registry `SourceId` that supplies the canonical evidence.
    #[must_use]
    pub const fn source_ref(&self) -> &SourceId {
        &self.source_ref
    }

    /// Verification-status classification.
    #[must_use]
    pub const fn verification_status(&self) -> VerificationStatus {
        self.verification_status
    }

    /// `introduced_in` version-sensitive fact (always present).
    #[must_use]
    pub const fn introduced_in(&self) -> &VersionFact {
        &self.introduced_in
    }

    /// `changed_in` exception field; `None` when not applicable.
    #[must_use]
    pub const fn changed_in(&self) -> Option<&VersionFact> {
        self.changed_in.as_ref()
    }

    /// `deprecated_in` exception field; `None` when not applicable.
    #[must_use]
    pub const fn deprecated_in(&self) -> Option<&VersionFact> {
        self.deprecated_in.as_ref()
    }

    /// `removed_in` exception field; `None` when not applicable.
    #[must_use]
    pub const fn removed_in(&self) -> Option<&VersionFact> {
        self.removed_in.as_ref()
    }

    /// `superseded_by` exception field; `None` when not applicable.
    #[must_use]
    pub const fn superseded_by(&self) -> Option<&'static str> {
        self.superseded_by
    }

    /// `kernel_dependency` exception field; `None` when not applicable.
    #[must_use]
    pub const fn kernel_dependency(&self) -> Option<&VersionFact> {
        self.kernel_dependency.as_ref()
    }
}

/// Static allowlist of source IDs from
/// `docs/research.md` (SRC-01 through SRC-14).
/// Runtime never reads the registry file; the test audit in
/// `tests/compatibility_audit.rs` parses the file and asserts this
/// slice matches the live registry exactly.
static KNOWN_SOURCE_IDS: [SourceId; 14] = [
    SourceId::from_static("SRC-01"),
    SourceId::from_static("SRC-02"),
    SourceId::from_static("SRC-03"),
    SourceId::from_static("SRC-04"),
    SourceId::from_static("SRC-05"),
    SourceId::from_static("SRC-06"),
    SourceId::from_static("SRC-07"),
    SourceId::from_static("SRC-08"),
    SourceId::from_static("SRC-09"),
    SourceId::from_static("SRC-10"),
    SourceId::from_static("SRC-11"),
    SourceId::from_static("SRC-12"),
    SourceId::from_static("SRC-13"),
    SourceId::from_static("SRC-14"),
];

/// Return the compiled allowlist of source IDs as a slice.
#[must_use]
pub fn known_source_ids() -> &'static [SourceId] {
    &KNOWN_SOURCE_IDS
}

/// Return `true` when `id` is in the compiled allowlist.
#[must_use]
pub fn is_known_source_id(id: &SourceId) -> bool {
    KNOWN_SOURCE_IDS.iter().any(|known| known == id)
}

/// Validate a compatibility record against the compiled allowlist.
///
/// Rejects any record (or any of its conditional exception fields)
/// whose `SourceId` is not in the allowlist, including the
/// `VersionFact::Verified { source_ref }` evidence source. Returning
/// the typed `Error::CompatibilityUnknownSource` discriminant lets a
/// caller branch on the failure mode without parsing prose.
///
/// # Errors
/// Returns [`Error::CompatibilityUnknownSource`] when the record's
/// `source_ref` or any conditional `Verified` evidence `source_ref`
/// is not in [`known_source_ids`].
pub fn validate_compatibility(record: &CompatibilityRecord) -> Result<(), Error> {
    if !is_known_source_id(record.source_ref()) {
        return Err(Error::CompatibilityUnknownSource(
            record.source_ref().clone(),
        ));
    }
    validate_version_fact(&record.introduced_in)?;
    if let Some(field) = record.changed_in() {
        validate_version_fact(field)?;
    }
    if let Some(field) = record.deprecated_in() {
        validate_version_fact(field)?;
    }
    if let Some(field) = record.removed_in() {
        validate_version_fact(field)?;
    }
    if let Some(field) = record.kernel_dependency() {
        validate_version_fact(field)?;
    }
    Ok(())
}

fn validate_version_fact(fact: &VersionFact) -> Result<(), Error> {
    if let VersionFact::Verified { source_ref } = fact {
        if !is_known_source_id(source_ref) {
            return Err(Error::CompatibilityUnknownSource(source_ref.clone()));
        }
    }
    Ok(())
}

/// Canonical compatibility record for the
/// `RestrictAddressFamilies=` directive.
///
/// When the host systemd version is unknown /
/// unverified, every version-sensitive field is the typed
/// `Unknown` or `Unverified` variant. No baseline, kernel, or
/// systemd version literal is fabricated. The evidence source is
/// `SRC-02` (systemd.resource-control(5) manual), which is the
/// authoritative manual page for the directive.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RestrictAddressFamilies;

impl RestrictAddressFamilies {
    /// Canonical `RestrictAddressFamilies=` compatibility record.
    /// The constant is built once via the same construction path a
    /// recommendation-rule seam would use; the validation invariant
    /// is exercised in `tests/compatibility_rejections.rs`.
    #[must_use]
    pub const fn record() -> CompatibilityRecord {
        // SRC-02 is the registry entry for `systemd.resource-control(5)`;
        // see `docs/research.md` (verified via
        // upstream-source confirmation on 2026-08-12).
        let source_ref: SourceId = SourceId::from_static("SRC-02");
        let record: CompatibilityRecord = CompatibilityRecord::new_unchecked(
            "RestrictAddressFamilies",
            // When systemd version is unknown/unverified, we
            // cannot claim `Supported` until the host
            // baseline is resolved.
            SupportStatus::Unknown,
            source_ref,
            VerificationStatus::Unverified,
            VersionFact::Unknown,
            None,
            None,
            None,
            None,
            None,
        );
        // The const allowlist contains SRC-02 and the VersionFact
        // is Unknown (no SourceId), so the validator would return
        // Ok by construction. The audit test
        // (`tests/compatibility_rejections.rs`) calls
        // `validate_compatibility(&record)` to lock the invariant.
        record
    }
}
