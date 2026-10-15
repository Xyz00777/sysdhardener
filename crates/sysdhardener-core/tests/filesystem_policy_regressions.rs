//! Regression coverage for version-gated filesystem candidates.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert directly on public recommendation values"
)]

use sysdhardener_core::filesystem::{
    FsAccessEvent, FsAggregator, derive_filesystem_findings_with_host,
};
use sysdhardener_core::{Capability, CoverageQuality, EventOutcome, SystemdVersion};

fn derive(paths: &[(&str, bool)], version: u32) -> Vec<sysdhardener_core::Finding> {
    let mut events = FsAggregator::new();
    for (path, write) in paths {
        events.record(FsAccessEvent::new(*path, *write, EventOutcome::Success));
    }
    derive_filesystem_findings_with_host(
        &events,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
        Some(SystemdVersion { major: version }),
    )
}

fn derive_without_host(paths: &[(&str, bool)]) -> Vec<sysdhardener_core::Finding> {
    let mut events = FsAggregator::new();
    for (path, write) in paths {
        events.record(FsAccessEvent::new(*path, *write, EventOutcome::Success));
    }
    sysdhardener_core::filesystem::derive_filesystem_findings(
        &events,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
    )
}

fn value<'a>(findings: &'a [sysdhardener_core::Finding], directive: &str) -> Option<&'a str> {
    findings
        .iter()
        .find(|finding| finding.directive() == directive)
        .and_then(sysdhardener_core::Finding::recommended_value)
}

#[test]
fn home_reads_keep_read_only_protection_candidate() {
    let findings = derive(&[("/home/alice/.config/app/settings", false)], 255);

    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
}

#[test]
fn home_writes_keep_read_only_candidate_and_allow_exact_written_parent() {
    let findings = derive(&[("/home/alice/data/dump.rdb", true)], 255);

    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
    assert_eq!(value(&findings, "ReadWritePaths"), Some("/home/alice/data"));
}

#[test]
fn home_writes_do_not_emit_read_only_without_read_write_paths_support() {
    for version in [214, 230] {
        let findings = derive(&[("/root/data/dump.rdb", true)], version);

        assert!(
            value(&findings, "ProtectHome").is_none(),
            "v{version} must not make observed home writes read-only without ReadWritePaths support"
        );
        assert!(value(&findings, "ReadWritePaths").is_none());
    }
}

#[test]
fn mixed_etc_and_home_writes_remain_unprotected_on_v230() {
    let findings = derive(
        &[("/etc/app/state.conf", true), ("/root/data/dump.rdb", true)],
        230,
    );

    assert_eq!(value(&findings, "ProtectSystem"), Some("yes"));
    assert!(value(&findings, "ProtectHome").is_none());
    assert!(value(&findings, "ReadWritePaths").is_none());
}

#[test]
fn home_writes_keep_supported_exception_at_v231_and_unknown_host() {
    let known = derive(&[("/root/data/dump.rdb", true)], 231);
    let unknown = derive_without_host(&[("/root/data/dump.rdb", true)]);

    for findings in [&known, &unknown] {
        assert_eq!(value(findings, "ProtectHome"), Some("read-only"));
        assert_eq!(value(findings, "ReadWritePaths"), Some("/root/data"));
    }
}

#[test]
fn strict_protection_exempts_home_and_separately_lists_home_write_path() {
    let findings = derive(&[("/root/data/dump.rdb", true)], 255);

    assert_eq!(value(&findings, "ProtectSystem"), Some("strict"));
    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
    assert_eq!(value(&findings, "ReadWritePaths"), Some("/root/data"));
}

#[test]
fn root_parent_write_cluster_does_not_claim_home_is_read_only() {
    let findings = derive(&[("/root", true)], 231);

    assert!(value(&findings, "ProtectHome").is_none());
    assert!(value(&findings, "ReadWritePaths").is_none());
}

#[test]
fn unrepresentable_nul_write_omits_blocking_candidates_and_exception() {
    let findings = derive(&[("/root/data/\0dump.rdb", true)], 255);

    assert!(value(&findings, "ProtectSystem").is_none());
    assert!(value(&findings, "ProtectHome").is_none());
    assert!(value(&findings, "ReadWritePaths").is_none());
}

#[test]
fn home_write_exception_does_not_expand_to_sibling_private_directories() {
    let findings = derive(&[("/root/data/dump.rdb", true)], 255);
    let paths = value(&findings, "ReadWritePaths").expect("write exception present");

    assert_eq!(paths, "/root/data");
    assert!(!paths.contains("/root/.ssh"));
}

#[test]
fn home_write_paths_remain_when_system_protection_is_omitted() {
    let findings = derive(
        &[
            ("/usr/local/share/app.db", true),
            ("/home/alice/data/db", true),
        ],
        255,
    );

    assert!(value(&findings, "ProtectSystem").is_none());
    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
    assert_eq!(
        value(&findings, "ReadWritePaths"),
        Some("/home/alice/data /usr/local/share")
    );
}

#[test]
fn mixed_system_etc_and_home_writes_preserve_home_exception_without_system_protection() {
    let findings = derive(
        &[
            ("/usr/lib/app/plugin.so", true),
            ("/etc/app/state.conf", true),
            ("/root/data/dump.rdb", true),
        ],
        255,
    );

    assert!(value(&findings, "ProtectSystem").is_none());
    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
    assert_eq!(
        value(&findings, "ReadWritePaths"),
        Some("/etc/app /root/data /usr/lib/app")
    );
}

#[test]
fn home_read_only_value_is_not_recommended_before_systemd_214() {
    let findings = derive(&[("/home/alice/.config/app/settings", false)], 210);

    assert!(value(&findings, "ProtectHome").is_none());
}

#[test]
fn protect_home_read_only_is_supported_from_systemd_214() {
    let findings = derive(&[("/home/alice/.config/app/settings", false)], 214);

    assert_eq!(value(&findings, "ProtectHome"), Some("read-only"));
}

#[test]
fn strict_and_read_write_candidates_obey_value_introduction_versions() {
    let older = derive(&[("/var/lib/app/db", true)], 230);
    let strict_since_232 = derive(&[("/var/lib/app/db", true)], 232);
    let paths_since_231 = derive(&[("/var/lib/app/db", true)], 231);

    assert_eq!(value(&older, "ProtectSystem"), Some("full"));
    assert!(value(&older, "ReadWritePaths").is_none());
    assert_eq!(value(&paths_since_231, "ProtectSystem"), Some("full"));
    assert_eq!(
        value(&paths_since_231, "ReadWritePaths"),
        Some("/var/lib/app")
    );
    assert_eq!(value(&strict_since_232, "ProtectSystem"), Some("strict"));
}

#[test]
fn quoted_write_path_escapes_systemd_quote_characters() {
    let findings = derive(&[("/home/alice/my \"data\"/dump.rdb", true)], 255);

    assert_eq!(
        value(&findings, "ReadWritePaths"),
        Some("\"/home/alice/my \\\"data\\\"\"")
    );
}

#[test]
fn restrict_address_families_introduction_is_systemd_211() {
    use sysdhardener_core::directive_introduced_in;

    assert_eq!(
        directive_introduced_in("RestrictAddressFamilies"),
        Some(211)
    );
}

#[test]
fn error_and_interrupted_home_writes_do_not_create_write_exceptions() {
    let mut events = FsAggregator::new();
    events.record(FsAccessEvent::new(
        "/home/alice/data/error.db",
        true,
        EventOutcome::Error,
    ));
    events.record(FsAccessEvent::new(
        "/root/data/interrupted.db",
        true,
        EventOutcome::Interrupted,
    ));
    let findings = derive_filesystem_findings_with_host(
        &events,
        Capability::ExpectedRoot,
        CoverageQuality::Complete,
        Some(SystemdVersion { major: 255 }),
    );

    assert_eq!(value(&findings, "ProtectHome"), Some("yes"));
    assert!(value(&findings, "ReadWritePaths").is_none());
}

#[test]
fn filesystem_validation_guidance_is_specific_to_candidate_directive() {
    let findings = derive(&[("/home/alice/data/db", true)], 255);
    let entries = sysdhardener_core::project_detailed(&findings);
    let guidance: Vec<(&str, &str)> = entries
        .entries()
        .iter()
        .map(|entry| (entry.directive(), entry.validation_procedure_text()))
        .collect();
    let home = guidance
        .iter()
        .find(|(directive, _)| *directive == "ProtectHome")
        .map(|(_, text)| *text)
        .expect("home validation guidance present");
    let write_paths = guidance
        .iter()
        .find(|(directive, _)| *directive == "ReadWritePaths")
        .map(|(_, text)| *text)
        .expect("write-path validation guidance present");

    assert_ne!(home, write_paths);
}
