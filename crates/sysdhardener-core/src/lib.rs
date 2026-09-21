//! `sysdhardener-core` - typed domain values, ports, and errors for the
//! deterministic evidence pipeline.
//!
//! This crate is the typed interior of the workspace. It owns the
//! versioned fixture/report envelope parsers ([`parse_fixture_v1`],
//! [`serialize_report_v1`]), the public value objects ([`Fixture`],
//! [`ObservedEvent`], [`AddressFamily`], [`EventOutcome`],
//! [`CoverageQuality`], [`Report`]), the newtype primitives
//! ([`SchemaVersion`], [`SourceId`], [`FixtureTimestamp`]), the typed
//! [`Error`], and the public ports ([`EventSource`], [`OutputSink`],
//! [`CapabilityProbe`], [`Capability`]).
//!
//! This crate ships the fixture-backed [`EventSource`] implementation
//! ([`FixtureEventSource`]), the real Linux capability probe
//! ([`ProcStatusCapabilityProbe`]), the three file sink adapters, the
//! single address-family recommendation rule, the two-view
//! projections, the logging seam ([`AnalysisInput`], [`run_analysis`],
//! [`RawEventLog`]), and the sink aggregation. The sibling
//! `sysdhardener-cli` binary consumes this crate through the public
//! re-exports below; private wire DTOs and helpers stay `pub(crate)`.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod aggregate;
mod analysis;
mod capability;
mod compatibility;
mod error;
pub mod filesystem;
mod finding;
mod fixture;
mod fixture_event_source;
mod fixture_events;
mod fixture_wire;
mod fs_cluster;
mod logging;
mod observed_event;
mod outcome;
mod path_norm;
mod ports;
mod probe;
mod projection;
#[cfg(feature = "testing")]
mod projection_seam;
mod recommendation;
mod report;
mod schema;
mod sink_outcome;
mod sinks;
mod sinks_render;
mod source_id;
mod systemd_version;
mod timestamp;

pub use aggregate::{
    AddressFamilyAggregate, AddressFamilyBundle, aggregate_address_family_evidence,
};
pub use analysis::{
    AnalysisInput, DEFAULT_RAW_EVENT_LOG_LIMIT, OutputSummary, run_analysis,
    run_analysis_from_fixture,
};
pub use capability::{
    ALL_CAPABILITIES, AMBIENT_CAPABILITIES_DIRECTIVE, CAPABILITY_DIRECTIVE, CAPABILITY_SOURCE_ID,
    LinuxCapability, is_capability_event, recommend_ambient_capabilities,
    recommend_capability_bounding_set, successfully_used_capabilities, syscall_to_capabilities,
    syscall_to_inherent_capabilities,
};
pub use compatibility::{
    CompatibilityRecord, RestrictAddressFamilies, SupportStatus, VerificationStatus, VersionFact,
    is_known_source_id, known_source_ids, validate_compatibility,
};
pub use error::{Error, SUPPORTED_FIXTURE_SCHEMA, SUPPORTED_REPORT_SCHEMA, SinkWriteFailure};
pub use finding::{
    Finding, recommend_ambient_capabilities_finding, recommend_capability_bounding_set_finding,
};
pub use fixture::{AddressFamily, CoverageQuality, EventOutcome, Fixture, parse_fixture_v1};
pub use fixture_event_source::FixtureEventSource;
pub use logging::RawEventLog;
pub use observed_event::ObservedEvent;
pub use outcome::{ProcessOutcome, exit_code_to_u8, usage_exit_code};
pub use path_norm::{normalize_path, normalize_path_str};
pub use ports::{Capability, CapabilityProbe, EventSource, OutputSink, combine_visibility};
#[cfg(feature = "testing")]
pub use probe::FixedCapabilityProbe;
pub use probe::{
    EffectiveUid, ProbeError, ProcStatusCapabilityProbe, parse_effective_uid,
    parse_status_visibility, read_proc_status,
};
pub use projection::{
    CONCISE_WARNING, ConciseProjection, DetailedEntry, DetailedProjection, project_concise,
    project_detailed,
};
#[cfg(feature = "testing")]
pub use projection_seam::{compatibility_risk_synthetic_for_test, finding_synthetic_for_test};
pub use recommendation::{
    CompatibilityRisk, ContradictionCondition, EventLoss, FindingBasis, ProvisionalStatus,
    ValidationProcedure, recommend_restrict_address_families,
};
pub use report::{Report, serialize_report_v1};
pub use schema::SchemaVersion;
pub use sink_outcome::{SinkWriteReport, SinkWriteSuccess, attempt_all_sinks};
pub use sinks::{ConciseFileSink, DetailedFileSink, JsonFileSink};
pub use source_id::SourceId;
pub use systemd_version::{
    SystemdVersion, directive_introduced_in, directive_supported, probe_host_systemd_version,
};
pub use timestamp::{FixtureTimestamp, check_fixture_window};
