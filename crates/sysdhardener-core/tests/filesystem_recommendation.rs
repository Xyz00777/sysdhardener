//! TDD: Tests for filesystem hardening recommendations (`ProtectSystem`, `ProtectHome`, `ProtectControlGroups`, `ReadWritePaths`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::redundant_closure_for_method_calls,
    clippy::indexing_slicing,
    reason = "tests use direct assertions on test outputs"
)]

use sysdhardener_core::filesystem::{FsAccessEvent, FsAggregator, derive_filesystem_findings};
use sysdhardener_core::{Capability, CoverageQuality, EventOutcome};

#[test]
fn clean_daemon_gets_protect_system_strict_protect_home_and_cgroups() {
    let mut aggregator = FsAggregator::new();

    // Reads /usr and /etc, writes only to /var/lib/mydaemon and /var/log/mydaemon
    aggregator.record(FsAccessEvent::new(
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        false, // read
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/etc/mydaemon/config.toml",
        false, // read
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/lib/mydaemon/data.db",
        true, // write
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/log/mydaemon/service.log",
        true, // write
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );

    let directives: Vec<&str> = findings.iter().map(|f| f.directive()).collect();
    assert!(
        directives.contains(&"ProtectSystem"),
        "Must recommend ProtectSystem"
    );
    assert!(
        directives.contains(&"ReadWritePaths"),
        "Must recommend ReadWritePaths"
    );
    assert!(
        directives.contains(&"ProtectHome"),
        "Must recommend ProtectHome"
    );
    assert!(
        directives.contains(&"ProtectControlGroups"),
        "Must recommend ProtectControlGroups"
    );

    // Check specific recommendation values
    let protect_system = findings
        .iter()
        .find(|f| f.directive() == "ProtectSystem")
        .unwrap();
    assert_eq!(protect_system.recommended_value(), Some("strict"));

    let read_write_paths = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .unwrap();
    assert!(
        read_write_paths
            .recommended_value()
            .unwrap()
            .contains("/var/lib/mydaemon")
    );
    assert!(
        read_write_paths
            .recommended_value()
            .unwrap()
            .contains("/var/log/mydaemon")
    );

    let protect_home = findings
        .iter()
        .find(|f| f.directive() == "ProtectHome")
        .unwrap();
    assert_eq!(protect_home.recommended_value(), Some("yes"));

    let protect_cgroups = findings
        .iter()
        .find(|f| f.directive() == "ProtectControlGroups")
        .unwrap();
    assert_eq!(protect_cgroups.recommended_value(), Some("yes"));
}

#[test]
fn daemon_writing_to_etc_falls_back_to_protect_system_yes() {
    let mut aggregator = FsAggregator::new();

    // Writes to /etc/foo.conf
    aggregator.record(FsAccessEvent::new(
        "/etc/foo.conf",
        true, // write
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    let protect_system = findings
        .iter()
        .find(|f| f.directive() == "ProtectSystem")
        .unwrap();
    // Since /etc was written to, cannot use strict or full, but can use yes
    assert_eq!(protect_system.recommended_value(), Some("yes"));
}

#[test]
fn daemon_writing_to_usr_disables_protect_system() {
    let mut aggregator = FsAggregator::new();

    // Writes to /usr/bin/plugin
    aggregator.record(FsAccessEvent::new(
        "/usr/bin/plugin",
        true, // write
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    assert!(!findings.iter().any(|f| f.directive() == "ProtectSystem"));
}

#[test]
fn daemon_accessing_home_gets_read_only_protect_home() {
    let mut aggregator = FsAggregator::new();

    // Reads /home/alice/.config
    aggregator.record(FsAccessEvent::new(
        "/home/alice/.config",
        false, // read
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    assert_eq!(
        findings
            .iter()
            .find(|finding| finding.directive() == "ProtectHome")
            .and_then(|finding| finding.recommended_value()),
        Some("read-only")
    );
}

#[test]
fn daemon_writing_cgroups_disables_protect_control_groups() {
    let mut aggregator = FsAggregator::new();

    // Writes to /sys/fs/cgroup/memory.max
    aggregator.record(FsAccessEvent::new(
        "/sys/fs/cgroup/memory.max",
        true, // write
        EventOutcome::Success,
    ));

    let findings = derive_filesystem_findings(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.directive() == "ProtectControlGroups")
    );
}

#[test]
fn daemon_without_etc_writes_on_systemd_older_than_232_gets_protect_system_full() {
    let mut aggregator = FsAggregator::new();
    aggregator.record(FsAccessEvent::new(
        "/usr/bin/daemon",
        false,
        EventOutcome::Success,
    ));
    aggregator.record(FsAccessEvent::new(
        "/var/lib/data.db",
        true,
        EventOutcome::Success,
    ));

    let host = Some(sysdhardener_core::SystemdVersion { major: 219 });
    let findings = sysdhardener_core::filesystem::derive_filesystem_findings_with_host(
        &aggregator,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
        host,
    );
    let protect_system = findings
        .iter()
        .find(|f| f.directive() == "ProtectSystem")
        .unwrap();
    assert_eq!(protect_system.recommended_value(), Some("full"));
}

#[test]
fn path_with_spaces_is_parsed_correctly() {
    use sysdhardener_core::{AddressFamily, FixtureTimestamp, ObservedEvent, SourceId};

    let event = ObservedEvent::new(
        SourceId::from_static("SRC-12"),
        "test-event".to_string(),
        FixtureTimestamp::from_raw_checked(1_000),
        AddressFamily::Other("capability"),
        EventOutcome::Success,
        "openat family=capability ret=3 path=/var/log/my custom service/app.log write=true"
            .to_string(),
    );

    let agg = FsAggregator::from_events(&[event]);
    assert_eq!(agg.events().len(), 1);
    let fs_ev = agg.events().first().unwrap();
    assert_eq!(fs_ev.path(), "/var/log/my custom service/app.log");
    assert!(fs_ev.is_write());
}

#[test]
fn path_with_spaces_is_quoted_in_read_write_paths() {
    let mut agg = FsAggregator::new();
    agg.record(FsAccessEvent::new(
        "/var/lib/my daemon/data.db",
        true,
        EventOutcome::Success,
    ));
    agg.record(FsAccessEvent::new(
        "/var/log/simple/app.log",
        true,
        EventOutcome::Success,
    ));

    let findings =
        derive_filesystem_findings(&agg, Capability::ExpectedRoot, CoverageQuality::Complete);
    let rw_paths = findings
        .iter()
        .find(|f| f.directive() == "ReadWritePaths")
        .expect("ReadWritePaths must be present");
    let val = rw_paths.recommended_value().expect("recommended value");
    assert!(val.contains("\"/var/lib/my daemon\""));
    assert!(val.contains("/var/log/simple"));
}

#[test]
fn degraded_capability_degrades_filesystem_finding_coverage() {
    let mut agg = FsAggregator::new();
    agg.record(FsAccessEvent::new(
        "/var/log/app.log",
        false,
        EventOutcome::Success,
    ));

    let findings =
        derive_filesystem_findings(&agg, Capability::DegradedNonRoot, CoverageQuality::Complete);
    for finding in &findings {
        assert_eq!(
            finding.coverage(),
            CoverageQuality::Degraded,
            "Non-root capability must degrade filesystem finding coverage"
        );
    }
}
