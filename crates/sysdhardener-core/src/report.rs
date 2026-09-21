//! Report envelope v1: private wire DTO + public typed values.
//!
//! The report envelope is the machine-readable output of the tool. The
//! typed `Report` carries the schema-version-bearing envelope and the
//! `Finding` collection produced by the provisional
//! recommendation; the same immutable `Finding` model is the
//! input to the projections. The public surface here is
//! deliberately minimal: [`Report::empty_v1`], [`Report::with_findings`],
//! [`Report::findings`], and [`serialize_report_v1`]. Wire DTOs never
//! escape the crate.

use serde::Serialize;

use crate::error::{Error, SUPPORTED_REPORT_SCHEMA};
use crate::finding::Finding;
use crate::schema::SchemaVersion;

/// A typed report envelope, version v1, carrying the `Finding`
/// collection.
///
/// The envelope borrows the findings it carries: the collection is
/// never cloned into the report, so a report built from an
/// in-memory `Finding` (or a slice of them) costs no copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report<'a> {
    schema_version: SchemaVersion,
    findings: &'a [Finding],
    /// The host systemd major version resolved by the runtime probe,
    /// when one was detected. `None` means "unknown host" (the
    /// conservative path: every directive emitted).
    pub(crate) host_systemd_version: Option<u32>,
    /// Syscalls whose ptrace stops are not delivered on this kernel:
    /// absence of these in the captured stream is an
    /// observation gap, not evidence of non-use.
    pub(crate) known_gaps: &'a [&'a str],
    /// The cgroup paths of the processes that produced the observed
    /// events, sorted and deduplicated. Empty for fixture input.
    pub(crate) observed_cgroups: &'a [String],
}

impl<'a> Report<'a> {
    /// Construct the empty v1 report envelope.
    #[must_use]
    pub const fn empty_v1() -> Self {
        Self {
            schema_version: SchemaVersion::v1_report(),
            findings: &[],
            host_systemd_version: None,
            known_gaps: &[],
            observed_cgroups: &[],
        }
    }

    /// Construct a v1 report envelope borrowing the given findings.
    /// Projections consume this same immutable collection.
    #[must_use]
    pub const fn with_findings(findings: &'a [Finding]) -> Self {
        Self {
            schema_version: SchemaVersion::v1_report(),
            findings,
            host_systemd_version: None,
            known_gaps: &[],
            observed_cgroups: &[],
        }
    }

    /// Construct a v1 report envelope borrowing the given findings and
    /// carrying the resolved host systemd version (the runtime probe).
    #[must_use]
    pub const fn with_findings_and_host(
        findings: &'a [Finding],
        host: Option<u32>,
        known_gaps: &'a [&'a str],
        observed_cgroups: &'a [String],
    ) -> Self {
        Self {
            schema_version: SchemaVersion::v1_report(),
            findings,
            host_systemd_version: host,
            known_gaps,
            observed_cgroups,
        }
    }

    /// Schema version of the envelope.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// The findings collection borrowed by the envelope.
    #[must_use]
    pub const fn findings(&self) -> &[Finding] {
        self.findings
    }

    /// The resolved host systemd major version, when probed.
    #[must_use]
    pub const fn host_systemd_version(&self) -> Option<u32> {
        self.host_systemd_version
    }

    /// The known observation gaps (undelivered syscalls, E-04).
    #[must_use]
    pub const fn known_gaps(&self) -> &[&str] {
        self.known_gaps
    }

    /// The observed cgroup paths, sorted and deduplicated.
    #[must_use]
    pub const fn observed_cgroups(&self) -> &[String] {
        self.observed_cgroups
    }
}

#[derive(Debug, Serialize)]
struct ReportWireV1<'a> {
    schema_version: u32,
    findings: &'a [Finding],
    /// The host systemd major version resolved by the runtime probe,
    /// when one was detected. Absent (`null`) when no systemd binary
    /// was reachable (conservative path: every directive emitted).
    host_systemd_version: Option<u32>,
    /// Syscalls whose ptrace stops are not delivered on this kernel
    /// (backlog E-04): absence is an observation gap, not non-use.
    known_gaps: &'a [&'a str],
    /// The cgroup paths of the processes that produced the events.
    observed_cgroups: &'a [String],
}

/// Serialize a v1 report envelope to wire bytes.
///
/// # Errors
/// Returns [`Error::SchemaUnknown`] if the report carries an
/// unsupported schema version, or [`Error::ReportSerialize`] if
/// `serde_json` itself fails (it cannot fail on the empty report,
/// but the function returns `Result` to match the future typed
/// findings surface).
pub fn serialize_report_v1(report: &Report<'_>) -> Result<Vec<u8>, Error> {
    let version = report.schema_version.get();
    if !SUPPORTED_REPORT_SCHEMA.contains(&version) {
        return Err(Error::SchemaUnknown {
            found: version,
            supported: SUPPORTED_REPORT_SCHEMA,
        });
    }
    let wire = ReportWireV1 {
        schema_version: version,
        findings: report.findings,
        host_systemd_version: report.host_systemd_version,
        known_gaps: report.known_gaps,
        observed_cgroups: report.observed_cgroups,
    };
    serde_json::to_vec(&wire).map_err(|e| Error::ReportSerialize(e.to_string()))
}
