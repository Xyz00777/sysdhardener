//! Filesystem access aggregation and hardening recommendations.
//!
//! Provides observation-driven recommendations for systemd filesystem
//! protection directives: `ProtectSystem=`, `ProtectHome=`,
//! `ProtectControlGroups=`, and `ReadWritePaths=`.

use crate::Capability;
use crate::filesystem_path::make_finding;
use crate::finding::Finding;
use crate::fixture::{CoverageQuality, EventOutcome};
use crate::fs_cluster::{cluster_write_paths, touches};
use crate::recommendation::EventLoss;

/// An observed filesystem access event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsAccessEvent {
    path: String,
    is_write: bool,
    outcome: EventOutcome,
}

impl FsAccessEvent {
    /// Construct a new filesystem access event.
    #[must_use]
    pub fn new(path: impl Into<String>, is_write: bool, outcome: EventOutcome) -> Self {
        Self {
            path: crate::path_norm::normalize_path_str(&path.into()),
            is_write,
            outcome,
        }
    }

    /// The accessed filesystem path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this access was a write operation.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        self.is_write
    }

    /// The outcome of the access syscall.
    #[must_use]
    pub const fn outcome(&self) -> EventOutcome {
        self.outcome
    }
}

/// Aggregator of filesystem access events observed during trace.
#[derive(Debug, Clone, Default)]
pub struct FsAggregator {
    events: Vec<FsAccessEvent>,
}

impl FsAggregator {
    /// Construct a new empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed access event.
    pub fn record(&mut self, event: FsAccessEvent) {
        self.events.push(event);
    }

    /// Slice of all recorded events.
    #[must_use]
    pub fn events(&self) -> &[FsAccessEvent] {
        &self.events
    }

    /// Build an aggregator from observed events by extracting filesystem evidence.
    #[must_use]
    pub fn from_events(events: &[crate::ObservedEvent]) -> Self {
        let mut agg = Self::new();
        for event in events {
            if let Some(fs_event) = parse_fs_event(event) {
                agg.record(fs_event);
            }
        }
        agg
    }
}

fn parse_fs_event(event: &crate::ObservedEvent) -> Option<FsAccessEvent> {
    let args = event.args();
    let path_start = if args.starts_with("path=") {
        Some(0)
    } else {
        args.find(" path=").map(|i| i + 1)
    }?;
    let after_path = args.get(path_start + 5..)?;
    let (path_str, is_write) = after_path.rfind(" write=").map_or_else(
        || {
            (
                after_path.split_whitespace().next().unwrap_or(after_path),
                false,
            )
        },
        |write_idx| {
            let p = after_path.get(..write_idx).unwrap_or(after_path);
            let w = after_path
                .get(write_idx + 7..)
                .is_some_and(|s| s.starts_with("true"));
            (p, w)
        },
    );
    if path_str.is_empty() {
        return None;
    }
    Some(FsAccessEvent::new(path_str, is_write, event.outcome()))
}

/// Derive provisional filesystem hardening recommendations from observed accesses,
/// taking into account event loss and host systemd version when available.
#[must_use]
pub fn derive_filesystem_findings_with_loss(
    aggregator: &FsAggregator,
    capability: Capability,
    coverage: CoverageQuality,
    event_loss: EventLoss,
    host: Option<crate::systemd_version::SystemdVersion>,
) -> Vec<Finding> {
    let effective_coverage = crate::combine_visibility(capability, coverage);
    let mut findings = Vec::new();

    let mut usr_or_boot_written = false;
    let mut etc_written = false;
    let mut home_accessed = false;
    let mut home_written = false;
    let mut cgroups_written = false;

    for event in aggregator.events() {
        if event.outcome() == EventOutcome::Error || event.outcome() == EventOutcome::Interrupted {
            continue;
        }
        let p = event.path();
        let in_home = touches(p, "/home") || touches(p, "/root") || touches(p, "/run/user");
        home_accessed |= in_home;
        home_written |= in_home && event.is_write();
        if event.is_write() {
            usr_or_boot_written |= touches(p, "/usr") || touches(p, "/boot");
            etc_written |= touches(p, "/etc");
            cgroups_written |= touches(p, "/sys/fs/cgroup");
        }
    }

    let read_write_paths_supported = host.is_none_or(|version| version.major >= 231);
    let write_paths = if read_write_paths_supported {
        cluster_write_paths(aggregator.events())
    } else {
        Vec::new()
    };
    let root_write_exception = write_paths.iter().any(|path| path == "/");
    let write_paths_representable = aggregator.events().iter().all(|event| {
        !event.is_write()
            || event.outcome() == EventOutcome::Error
            || event.outcome() == EventOutcome::Interrupted
            || !event.path().contains('\0')
    });
    let write_paths_value = write_paths_representable
        .then(|| crate::filesystem_path::serialize_write_paths(&write_paths))
        .flatten();

    if !usr_or_boot_written && host.is_none_or(|version| version.major >= 214) {
        let val = if etc_written {
            "yes"
        } else if host.is_some_and(|version| version.major < 232) {
            "full"
        } else {
            "strict"
        };
        if val != "strict" || write_paths_value.is_some() {
            findings.push(make_finding(
                "ProtectSystem",
                Some(val.to_owned()),
                effective_coverage,
                event_loss,
            ));
        }
    }

    if !home_accessed && host.is_none_or(|version| version.major >= 214) {
        findings.push(make_finding(
            "ProtectHome",
            Some("yes".into()),
            effective_coverage,
            event_loss,
        ));
    } else if host.is_none_or(|version| version.major >= 214)
        && !root_write_exception
        && (!home_written
            || read_write_paths_supported
                && write_paths_value
                    .as_deref()
                    .is_some_and(|value| !value.is_empty()))
    {
        findings.push(make_finding(
            "ProtectHome",
            Some("read-only".into()),
            effective_coverage,
            event_loss,
        ));
    }

    if read_write_paths_supported
        && !(home_accessed && root_write_exception)
        && write_paths_value
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        findings.push(make_finding(
            "ReadWritePaths",
            write_paths_value,
            effective_coverage,
            event_loss,
        ));
    }
    if !cgroups_written && host.is_none_or(|version| version.major >= 232) {
        findings.push(make_finding(
            "ProtectControlGroups",
            Some("yes".into()),
            effective_coverage,
            event_loss,
        ));
    }

    findings
}

/// Derive provisional filesystem hardening recommendations from observed accesses,
/// taking into account the host systemd version when available.
#[must_use]
pub fn derive_filesystem_findings_with_host(
    aggregator: &FsAggregator,
    capability: Capability,
    coverage: CoverageQuality,
    host: Option<crate::systemd_version::SystemdVersion>,
) -> Vec<Finding> {
    derive_filesystem_findings_with_loss(
        aggregator,
        capability,
        coverage,
        EventLoss {
            seen_events: 0,
            dropped_events: 0,
        },
        host,
    )
}

/// Derive provisional filesystem hardening recommendations from observed accesses.
#[must_use]
pub fn derive_filesystem_findings(
    aggregator: &FsAggregator,
    capability: Capability,
    coverage: CoverageQuality,
) -> Vec<Finding> {
    derive_filesystem_findings_with_host(aggregator, capability, coverage, None)
}
