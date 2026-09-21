//! Deterministic analysis orchestration with structured lifecycle,
//! decision, and bounded raw-event logging.
//!
//! [`run_analysis`] is the first seam that composes the pure core into
//! one call: parse envelope, aggregate evidence, derive the single
//! provisional candidate, project the two views, serialize the report.
//! The seam itself is pure — no I/O, no wall clock, no sink, no process
//! outcome — and all observability flows through `tracing` into
//! whatever writer the process installed (stderr in the CLI, an
//! injected writer in tests). The diagnostic stream therefore never
//! touches the report outputs.
//!
//! Log-level contract:
//! - `INFO`  lifecycle: phase boundaries plus the fixture envelope
//!   summary and the final finding count;
//! - `WARN`  gaps: declared event loss, degraded visibility, degraded
//!   effective coverage;
//! - `DEBUG` aggregated evidence and mapping decisions;
//! - `ERROR` fatal phase failure, followed by the typed error return;
//! - raw individual events only through [`crate::logging::RawEventLog`]
//!   at `TRACE`, bounded and truncation-reported.
//!
//! The recommendation is fully deterministic in the input: the log
//! level is a verbosity control, never a confidence input, so the
//! report output is byte-identical at every level.

use crate::aggregate::{AddressFamilyBundle, aggregate_address_family_evidence};
use crate::compatibility::CompatibilityRecord;
use crate::error::Error;
use crate::finding::Finding;
use crate::fixture::{CoverageQuality, Fixture, parse_fixture_v1};
use crate::logging::RawEventLog;
use crate::observed_event::ObservedEvent;
use crate::ports::Capability;
use crate::projection::{ConciseProjection, DetailedProjection, project_concise, project_detailed};
use crate::recommendation::recommend_restrict_address_families;
use crate::report::{Report, serialize_report_v1};

/// Default cap for raw-event TRACE lines per run.
///
/// The default keeps raw event volume bounded without configuration;
/// callers can raise or lower it per run through
/// [`AnalysisInput::raw_event_log_limit`].
pub const DEFAULT_RAW_EVENT_LOG_LIMIT: usize = 10;

/// Everything one deterministic analysis run needs to know.
#[derive(Debug)]
pub struct AnalysisInput<'a> {
    /// Raw wire bytes of a v1 fixture envelope.
    pub fixture_bytes: &'a [u8],
    /// Process visibility classification for the run.
    pub visibility: Capability,
    /// Registry compatibility evidence for the directive.
    pub compatibility: &'a CompatibilityRecord,
    /// Maximum number of raw events to emit at `TRACE`; `0` disables.
    pub raw_event_log_limit: usize,
}

/// The recommendation surface produced by one analysis run: the typed
/// findings plus the two projections and the serialized report bytes.
#[derive(Debug)]
pub struct OutputSummary {
    /// The single provisional address-family candidate with all
    /// mandatory labels.
    pub finding: Finding,
    /// The provisional `CapabilityBoundingSet=` candidate (empty
    /// recommended set when no capability evidence was observed).
    pub capability_finding: Finding,
    /// The provisional `AmbientCapabilities=` candidate (the
    /// capabilities the service provably used; empty when no
    /// capability evidence was observed).
    pub ambient_finding: Finding,
    /// The evidence-bearing findings, in order: the address-family
    /// finding (when address-family evidence exists) and the
    /// capability finding (when capability evidence exists). The
    /// sinks render this list; evidence-less findings are excluded.
    pub findings: Vec<Finding>,
    /// Detailed view derived from the findings.
    pub detailed: DetailedProjection,
    /// Concise view (warning line + setting lines).
    pub concise: ConciseProjection,
    /// Serialized v1 report envelope bytes.
    pub report_bytes: Vec<u8>,
    /// The pids of the processes that produced the observed events,
    /// sorted and deduplicated. Empty for fixture input (fixture
    /// events carry no pid); populated by the live observer so the
    /// detailed report can attribute evidence across the service
    /// tree when `--show-pids` is selected.
    pub observed_pids: Vec<i32>,
    /// Syscalls whose ptrace stops are not delivered on this kernel
    /// (backlog E-04): absence of these in the captured stream is an
    /// observation gap, not evidence of non-use. Empty for fixture
    /// input.
    pub known_gaps: Vec<&'static str>,
    /// The cgroup paths of the processes that produced the observed
    /// events, sorted and deduplicated. Empty for fixture input.
    pub observed_cgroups: Vec<String>,
}

/// Run the deterministic analysis pipeline over one fixture envelope.
///
/// Phases are parse, aggregate, recommend, project, serialize. Every
/// phase boundary is logged at `INFO` with stable machine fields; gaps
/// warn at `WARN`; evidence and mapping decisions log at `DEBUG`; raw
/// events flow through a bounded [`RawEventLog`] at `TRACE`. On the
/// first failing phase an `ERROR` event is emitted and the typed
/// [`Error`] is returned.
///
/// # Errors
/// Returns the typed [`Error`] of the first failing phase (parse,
/// aggregate, recommend, project, or serialize).
pub fn run_analysis(input: &AnalysisInput<'_>) -> Result<OutputSummary, Error> {
    let fixture = parse_fixture(input.fixture_bytes)?;
    run_analysis_from_fixture(
        &fixture,
        input.visibility,
        input.compatibility,
        input.raw_event_log_limit,
        None,
        &[],
    )
}

/// Run the deterministic analysis pipeline over an already-parsed
/// [`Fixture`]. Shared by the fixture path ([`run_analysis`]) and the
/// live-observer path, so both evidence sources run the same engine.
///
/// `host` is the resolved host systemd version (runtime probe). The
/// gate marks each finding's `host_supported` flag: directives the
/// host does not support are skipped by the projections and flagged
/// in the report.
///
/// # Errors
/// Returns the typed [`Error`] of the first failing phase (aggregate,
/// recommend, project, or serialize).
pub fn run_analysis_from_fixture(
    fixture: &Fixture,
    visibility: Capability,
    compatibility: &CompatibilityRecord,
    raw_event_log_limit: usize,
    host: Option<crate::systemd_version::SystemdVersion>,
    known_gaps: &[&'static str],
) -> Result<OutputSummary, Error> {
    let bundle = aggregate_evidence(fixture, raw_event_log_limit)?;
    let mut finding = derive_candidate(&bundle, visibility, compatibility)?;
    // The capability recommendation is only meaningful when the
    // observer actually captured capability evidence. Fixture input
    // (and live runs with no capability syscalls) must not produce a
    // "drop every capability" candidate.
    let capability_events: Vec<ObservedEvent> = fixture
        .events()
        .iter()
        .filter(|e| crate::capability::is_capability_event(e))
        .cloned()
        .collect();
    let mut capability_finding = crate::finding::recommend_capability_bounding_set_finding(
        &capability_events,
        finding.coverage(),
        finding.event_loss(),
        compatibility,
    );
    // AmbientCapabilities= re-grants the capabilities the service
    // provably used; meaningful only when capability evidence exists.
    let ambient_finding = crate::finding::recommend_ambient_capabilities_finding(
        &capability_events,
        finding.coverage(),
        finding.event_loss(),
        compatibility,
    );
    // Version gate: mark each finding's host_supported flag. The
    // projections skip unsupported directives and the report records
    // the flag so the machine artifact explains the decision.
    let gate = |f: &mut Finding| {
        let introduced = crate::systemd_version::directive_introduced_in(f.directive());
        f.host_supported =
            introduced.is_none_or(|major| crate::systemd_version::directive_supported(host, major));
    };
    gate(&mut finding);
    gate(&mut capability_finding);
    let mut ambient_finding = ambient_finding;
    gate(&mut ambient_finding);
    let mut findings: Vec<Finding> = Vec::new();
    if bundle
        .entries()
        .any(|e| crate::recommendation::KNOWN_FAMILIES.contains(&e.family()))
    {
        findings.push(finding.clone());
    }
    if !capability_events.is_empty() {
        findings.push(capability_finding.clone());
        findings.push(ambient_finding.clone());
    }
    let fs_agg = crate::filesystem::FsAggregator::from_events(fixture.events());
    if !fs_agg.events().is_empty() {
        for mut f in crate::filesystem::derive_filesystem_findings_with_loss(
            &fs_agg,
            visibility,
            finding.coverage(),
            finding.event_loss(),
            host,
        ) {
            gate(&mut f);
            findings.push(f);
        }
    }
    let (detailed, concise) = project_outputs(&findings)?;
    let observed_pids = fixture.observed_pids();
    let observed_cgroups = fixture.observed_cgroups();
    let report_bytes = serialize_output(&findings, host, known_gaps, &observed_cgroups)?;
    Ok(OutputSummary {
        finding,
        capability_finding,
        ambient_finding,
        findings,
        detailed,
        concise,
        report_bytes,
        observed_pids,
        known_gaps: known_gaps.to_vec(),
        observed_cgroups,
    })
}

fn parse_fixture(bytes: &[u8]) -> Result<Fixture, Error> {
    let fixture = parse_fixture_v1(bytes).map_err(|e| phase_failed("parse", e))?;
    tracing::info!(
        target: "sysdhardener.analysis",
        phase = "parse",
        fixture_id = %fixture.fixture_id(),
        schema_version = fixture.schema_version().get(),
        seen_events = fixture.seen_events(),
        dropped_events = fixture.dropped_events(),
        "fixture envelope parsed"
    );
    Ok(fixture)
}

fn aggregate_evidence(
    fixture: &Fixture,
    raw_event_log_limit: usize,
) -> Result<AddressFamilyBundle, Error> {
    let bundle = aggregate_address_family_evidence(fixture.events(), fixture)
        .map_err(|e| phase_failed("aggregate", e))?;
    let mut raw_events = RawEventLog::new(raw_event_log_limit);
    for (index, event) in fixture.events().iter().enumerate() {
        raw_events.record(index, event);
    }
    raw_events.finish(fixture.events().len());
    tracing::info!(
        target: "sysdhardener.analysis",
        phase = "aggregate",
        "evidence aggregated"
    );
    if fixture.dropped_events() > 0 {
        tracing::warn!(
            target: "sysdhardener.analysis",
            phase = "aggregate",
            dropped_events = fixture.dropped_events(),
            coverage = ?bundle.coverage(),
            "declared event loss; the recommendation reflects incomplete observation"
        );
    }
    for entry in bundle.entries() {
        tracing::debug!(
            target: "sysdhardener.analysis",
            phase = "aggregate",
            aggregate_key = %entry.key(),
            aggregate_count = entry.count(),
            aggregate_family = ?entry.family(),
            "per-family evidence"
        );
    }
    Ok(bundle)
}

fn derive_candidate(
    bundle: &AddressFamilyBundle,
    visibility: Capability,
    compatibility: &CompatibilityRecord,
) -> Result<Finding, Error> {
    let finding = recommend_restrict_address_families(bundle, visibility, compatibility)
        .map_err(|e| phase_failed("recommend", e))?;
    tracing::info!(
        target: "sysdhardener.analysis",
        phase = "recommend",
        directive = %finding.directive(),
        "candidate derived"
    );
    if matches!(
        visibility,
        Capability::DegradedNonRoot | Capability::Unknown
    ) {
        tracing::warn!(target: "sysdhardener.analysis", phase = "recommend", visibility = ?visibility, "degraded visibility; complete observation cannot be established");
    }
    if finding.coverage() == CoverageQuality::Degraded {
        tracing::warn!(target: "sysdhardener.analysis", phase = "recommend", coverage = ?finding.coverage(), "effective coverage is degraded; absence remains provisional");
    }
    tracing::debug!(
        target: "sysdhardener.analysis",
        phase = "recommend",
        basis = ?finding.basis(),
        provisional = ?finding.provisional(),
        recommended_families = ?finding.recommended_families(),
        "mapping decision"
    );
    Ok(finding)
}

fn project_outputs(findings: &[Finding]) -> Result<(DetailedProjection, ConciseProjection), Error> {
    let detailed = project_detailed(findings);
    let concise = if findings.is_empty() {
        ConciseProjection::empty()
    } else {
        project_concise(findings).map_err(|e| phase_failed("project", e))?
    };
    tracing::info!(target: "sysdhardener.analysis", phase = "project", "outputs projected");
    Ok((detailed, concise))
}

fn serialize_output(
    findings: &[Finding],
    host: Option<crate::systemd_version::SystemdVersion>,
    known_gaps: &[&'static str],
    observed_cgroups: &[String],
) -> Result<Vec<u8>, Error> {
    let report = Report::with_findings_and_host(
        findings,
        host.map(|v| v.major),
        known_gaps,
        observed_cgroups,
    );
    let report_bytes = serialize_report_v1(&report).map_err(|e| phase_failed("serialize", e))?;
    tracing::info!(target: "sysdhardener.analysis", phase = "serialize", findings = findings.len(), bytes = report_bytes.len(), "analysis complete");
    Ok(report_bytes)
}

/// Log a fatal phase failure at `ERROR`, then return the error.
fn phase_failed(phase: &'static str, error: Error) -> Error {
    tracing::error!(
        target: "sysdhardener.analysis",
        phase,
        error = %error,
        "analysis phase failed"
    );
    error
}
