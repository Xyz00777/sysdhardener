//! Pipeline integration tests for filesystem hardening recommendations.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::redundant_closure_for_method_calls,
    clippy::indexing_slicing,
    reason = "tests use direct assertions on test outputs"
)]

use sysdhardener_core::filesystem::{FsAccessEvent, FsAggregator, derive_filesystem_findings};
use sysdhardener_core::{
    AddressFamily, Capability, CoverageQuality, EventOutcome, Fixture, FixtureTimestamp,
    ObservedEvent, RestrictAddressFamilies, SourceId, run_analysis_from_fixture,
};

#[test]
fn filesystem_findings_project_to_concise_view() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/var/log/mydaemon/log.txt",
        true,
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let concise = sysdhardener_core::project_concise(&findings).expect("project concise succeeds");
    let lines = concise.lines();
    assert_eq!(
        lines.first().map(String::as_str),
        Some(sysdhardener_core::CONCISE_WARNING)
    );
    assert!(lines.iter().any(|l| l == "ProtectSystem=strict"));
    assert!(
        lines
            .iter()
            .any(|l| l == "ReadWritePaths=/var/log/mydaemon")
    );
    assert!(lines.iter().any(|l| l == "ProtectHome=yes"));
    assert!(lines.iter().any(|l| l == "ProtectControlGroups=yes"));
}

#[test]
fn write_path_subdirectories_are_subsumed_by_parent() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/var/lib/app/db.sqlite",
        true,
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/lib/app/sub/nested.db",
        true,
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let rwp = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .unwrap();
    assert_eq!(rwp.recommended_value(), Some("/var/lib/app"));
}

#[test]
fn aggregator_extracts_fs_events_from_observed_events() {
    let ev1 = ObservedEvent::new(
        SourceId::from_static("SRC-12"),
        "ev-1".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "openat family=capability ret=3 path=/etc/foo.conf write=false".to_string(),
    );
    let ev2 = ObservedEvent::new(
        SourceId::from_static("SRC-12"),
        "ev-2".to_string(),
        FixtureTimestamp::from_raw_checked(101),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "openat family=capability ret=4 path=/var/lib/app/data.db write=true".to_string(),
    );
    let aggregator = FsAggregator::from_events(&[ev1, ev2]);
    assert_eq!(aggregator.events().len(), 2);
    assert_eq!(
        aggregator.events().first().map(FsAccessEvent::path),
        Some("/etc/foo.conf")
    );
    assert_eq!(
        aggregator.events().first().map(FsAccessEvent::is_write),
        Some(false)
    );
    assert_eq!(
        aggregator.events().get(1).map(FsAccessEvent::path),
        Some("/var/lib/app/data.db")
    );
    assert_eq!(
        aggregator.events().get(1).map(FsAccessEvent::is_write),
        Some(true)
    );
}

#[test]
fn analysis_pipeline_includes_filesystem_findings_when_present() {
    let events = vec![
        ObservedEvent::new(
            SourceId::from_static("SRC-12"),
            "ev-1".to_string(),
            FixtureTimestamp::from_raw_checked(100),
            AddressFamily::Other("capability"),
            EventOutcome::Success,
            "openat family=capability ret=3 path=/etc/foo.conf write=false".to_string(),
        ),
        ObservedEvent::new(
            SourceId::from_static("SRC-12"),
            "ev-2".to_string(),
            FixtureTimestamp::from_raw_checked(101),
            AddressFamily::Other("capability"),
            EventOutcome::Success,
            "openat family=capability ret=4 path=/var/lib/app/data.db write=true".to_string(),
        ),
    ];
    let fixture = Fixture::from_events(events);
    let summary = run_analysis_from_fixture(
        &fixture,
        Capability::ExpectedRoot,
        &RestrictAddressFamilies::record(),
        10,
        None,
        &[],
    )
    .expect("analysis succeeds");

    let directives: Vec<&str> = summary
        .findings
        .iter()
        .map(sysdhardener_core::Finding::directive)
        .collect();
    assert!(
        directives.contains(&"ProtectSystem"),
        "Must contain ProtectSystem"
    );
    assert!(
        directives.contains(&"ReadWritePaths"),
        "Must contain ReadWritePaths"
    );
    assert!(
        directives.contains(&"ProtectHome"),
        "Must contain ProtectHome"
    );
    assert!(
        directives.contains(&"ProtectControlGroups"),
        "Must contain ProtectControlGroups"
    );
}

#[test]
fn root_directory_subsumes_subdirectories() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/file_in_root",
        true,
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/log/app.log",
        true,
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let rwp = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .unwrap();
    assert_eq!(rwp.recommended_value(), Some("/"));
}

#[test]
fn empty_path_events_are_ignored() {
    let ev = ObservedEvent::new(
        SourceId::from_static("SRC-12"),
        "ev-empty".to_string(),
        FixtureTimestamp::from_raw_checked(100),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "openat family=capability ret=3 path= write=false".to_string(),
    );
    let aggregator = FsAggregator::from_events(&[ev]);
    assert!(aggregator.events().is_empty());
}

#[test]
fn paths_with_dot_dot_are_lexically_normalized() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/usr/../var/log/app.log",
        true,
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let ps = findings.iter().find(|f| f.directive() == "ProtectSystem");
    assert!(ps.is_some(), "ProtectSystem must still be recommended");

    let rwp = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .unwrap();
    assert_eq!(rwp.recommended_value(), Some("/var/log"));
}

#[test]
fn relative_paths_with_dot_dot_subsume_properly() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/var/lib/mydaemon/config/../data/db1.sqlite",
        true,
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/lib/mydaemon/data/db2.sqlite",
        true,
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let rwp = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .unwrap();
    assert_eq!(rwp.recommended_value(), Some("/var/lib/mydaemon/data"));
}
