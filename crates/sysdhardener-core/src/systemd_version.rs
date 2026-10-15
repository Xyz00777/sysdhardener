//! Host systemd version detection and compatibility gating.
//!
//! The recommendation engine emits provisional hardening directives
//! (`RestrictAddressFamilies=`, `CapabilityBoundingSet=~CAP_X`, ...).
//! Each directive has an "introduced in" systemd version (the
//! capability map's Part 2/4 tables, SRC-01/SRC-02). This module
//! probes the *host* systemd version at runtime and decides whether
//! a directive is compatible with the host — so the tool never
//! recommends a directive the host's systemd does not support.
//!
//! The probe detects the host systemd version empirically: it runs
//! `systemd --version` and parses the first line. When no systemd
//! binary is reachable (e.g. a Nix dev shell), the probe returns
//! `None` and the engine falls back to the conservative behavior:
//! every directive is emitted with its provisional label, exactly as
//! before the gate existed.

use std::process::Command;

/// A parsed systemd version (`major[.minor...]`, e.g. 255).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemdVersion {
    /// The major version number (systemd versions are 255, 240, ...).
    pub major: u32,
}

impl SystemdVersion {
    /// Parse the first line of `systemd --version` output.
    ///
    /// The canonical first line is `systemd 255 (255.5-1-arch)`. The
    /// parser is deliberately strict: it reads `systemd <N>` and
    /// ignores the parenthesized detail. Returns `None` for any
    /// shape that does not match, so an unexpected host never
    /// silently fabricates a version.
    #[must_use]
    pub fn parse_version_output(first_line: &str) -> Option<Self> {
        let trimmed = first_line.trim();
        let rest = trimmed.strip_prefix("systemd")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let rest = rest.trim_start();
        let major_str = rest
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("");
        if major_str.is_empty() {
            return None;
        }
        let major: u32 = major_str.parse().ok()?;
        Some(Self { major })
    }
}

/// Whether a directive introduced in `since_version` is compatible
/// with the host.
///
/// `None` host (no systemd detected) is treated as **compatible with
/// warning**: the engine cannot verify, so it keeps the directive
/// with its provisional label rather than silently dropping it.
#[must_use]
pub const fn directive_supported(host: Option<SystemdVersion>, introduced_in_major: u32) -> bool {
    match host {
        Some(host) => host.major >= introduced_in_major,
        None => true,
    }
}

/// Probe the host systemd version by querying `systemctl` or `systemd`.
///
/// Probes `systemctl` first (canonical tool on `$PATH` across Linux distributions),
/// then falls back to `systemd` and standard daemon paths. Returns `None` when
/// no binary is reachable or its output cannot be parsed.
#[must_use]
pub fn probe_host_systemd_version() -> Option<SystemdVersion> {
    for cmd in &[
        "systemctl",
        "/usr/bin/systemctl",
        "/bin/systemctl",
        "systemd",
        "/usr/lib/systemd/systemd",
        "/lib/systemd/systemd",
    ] {
        if let Ok(output) = Command::new(cmd).arg("--version").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(v) = text.lines().find_map(SystemdVersion::parse_version_output) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// The systemd version that introduced a hardening directive.
///
/// Upstream provenance:
/// - `CapabilityBoundingSet=` has been supported since systemd v1.
/// - `AmbientCapabilities=` was introduced in systemd v229 (SRC-01).
/// - `RestrictAddressFamilies=` was introduced in systemd v211 (v211/NEWS).
#[must_use]
pub fn directive_introduced_in(directive: &str) -> Option<u32> {
    match directive {
        "CapabilityBoundingSet" => Some(1),
        "AmbientCapabilities" => Some(229),
        "RestrictAddressFamilies" => Some(211),
        "ProtectSystem" | "ProtectHome" => Some(214),
        "ProtectControlGroups" => Some(232),
        "ReadWritePaths" => Some(231),
        _ => None,
    }
}
