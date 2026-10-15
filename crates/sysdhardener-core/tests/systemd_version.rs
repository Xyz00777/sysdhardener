//! Unit tests for the systemd version parser and the directive gate.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests use direct assertions on the public version-gate contract"
)]

use sysdhardener_core::{SystemdVersion, directive_introduced_in, directive_supported};

#[test]
fn parses_canonical_systemd_version_line() {
    let v = SystemdVersion::parse_version_output("systemd 255 (255.5-1-arch)")
        .expect("canonical line parses");
    assert_eq!(v.major, 255);
}

#[test]
fn parses_plain_major_only() {
    let v = SystemdVersion::parse_version_output("systemd 240").expect("plain major parses");
    assert_eq!(v.major, 240);
}

#[test]
fn parses_systemctl_version_output() {
    let v = SystemdVersion::parse_version_output("systemd 261 (261.1)")
        .expect("systemctl style output parses");
    assert_eq!(v.major, 261);
}

#[test]
fn parses_version_line_with_leading_or_trailing_whitespace() {
    let v = SystemdVersion::parse_version_output("  systemd 252 (252.34-1~deb12u1)\r\n")
        .expect("line with whitespace parses");
    assert_eq!(v.major, 252);
}

#[test]
fn parses_version_line_with_multiple_spaces_or_tabs() {
    let v1 = SystemdVersion::parse_version_output("systemd   256 (256.1)")
        .expect("multiple spaces parse");
    assert_eq!(v1.major, 256);
    let v2 = SystemdVersion::parse_version_output("systemd\t255").expect("tab parses");
    assert_eq!(v2.major, 255);
}

#[test]
fn parses_version_line_with_lossy_utf8() {
    let raw = b"systemd 256 (256.4-1.fc40)\n+PAM +AUDIT \xff\xfe\n";
    let text = String::from_utf8_lossy(raw);
    let v = text.lines().find_map(SystemdVersion::parse_version_output);
    assert_eq!(v, Some(SystemdVersion { major: 256 }));
}

#[test]
fn probe_finds_systemd_version_if_systemctl_available() {
    let has_systemctl = std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if has_systemctl {
        let probe = sysdhardener_core::probe_host_systemd_version();
        assert!(
            probe.is_some(),
            "probe must resolve systemd version when systemctl is present on the host"
        );
    }
}

#[test]
fn rejects_unparseable_lines() {
    assert!(SystemdVersion::parse_version_output("").is_none());
    assert!(SystemdVersion::parse_version_output("systemd").is_none());
    assert!(SystemdVersion::parse_version_output("systemd abc").is_none());
    assert!(SystemdVersion::parse_version_output("not-systemd 255").is_none());
}

#[test]
fn gate_accepts_host_at_or_above_introduced_version() {
    let host = Some(SystemdVersion { major: 255 });
    assert!(
        directive_supported(host, 235),
        "v255 supports v235 directives"
    );
    assert!(
        directive_supported(host, 255),
        "v255 supports v255 directives"
    );
}

#[test]
fn gate_rejects_host_below_introduced_version() {
    let host = Some(SystemdVersion { major: 234 });
    assert!(
        !directive_supported(host, 235),
        "v234 does not support v235 directives"
    );
}

#[test]
fn gate_without_host_is_conservative() {
    // No systemd detected: keep every directive (provisional label).
    assert!(directive_supported(None, 235));
    assert!(directive_supported(None, 999));
}

#[test]
fn known_directives_have_introduced_versions() {
    assert_eq!(directive_introduced_in("CapabilityBoundingSet"), Some(1));
    assert_eq!(directive_introduced_in("AmbientCapabilities"), Some(229));
    assert_eq!(
        directive_introduced_in("RestrictAddressFamilies"),
        Some(211)
    );
    assert_eq!(directive_introduced_in("UnknownDirective"), None);
}

#[test]
fn restrict_address_families_is_unsupported_before_211_and_supported_at_211() {
    for (major, supported) in [(210, false), (211, true), (234, true), (235, true)] {
        assert_eq!(
            directive_supported(Some(SystemdVersion { major }), 211),
            supported,
            "unexpected RAF support at systemd v{major}"
        );
    }
}

#[test]
fn fixture_analysis_gates_findings_by_host_version() {
    // The fixture path runs the same engine as the live observer; the
    // host version gates each finding's host_supported flag. A v200
    // host must flag every v235+ directive as unsupported; a v255
    // host must support them all.
    use sysdhardener_core::{
        Capability, Fixture, RestrictAddressFamilies, parse_fixture_v1, run_analysis_from_fixture,
    };

    let bytes = std::fs::read("tests/fixtures/happy.json").expect("fixture readable");
    let fixture: Fixture = parse_fixture_v1(&bytes).expect("fixture parses");
    let compat = RestrictAddressFamilies::record();

    let old_host = run_analysis_from_fixture(
        &fixture,
        Capability::ExpectedRoot,
        &compat,
        10,
        Some(SystemdVersion { major: 200 }),
        &[],
    )
    .expect("analysis with old host");
    for finding in &old_host.findings {
        assert!(
            !finding.host_supported(),
            "v200 host must flag {} as unsupported",
            finding.directive()
        );
    }

    let new_host = run_analysis_from_fixture(
        &fixture,
        Capability::ExpectedRoot,
        &compat,
        10,
        Some(SystemdVersion { major: 255 }),
        &[],
    )
    .expect("analysis with new host");
    for finding in &new_host.findings {
        assert!(
            finding.host_supported(),
            "v255 host must support {}",
            finding.directive()
        );
    }

    let no_host =
        run_analysis_from_fixture(&fixture, Capability::ExpectedRoot, &compat, 10, None, &[])
            .expect("analysis without host");
    for finding in &no_host.findings {
        assert!(
            finding.host_supported(),
            "no host must be conservative (support {})",
            finding.directive()
        );
    }
}
