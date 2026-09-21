//! Capability-probe happy-path tests: synthetic root/non-root
//! `/proc/self/status` text, the exhaustive capability→coverage
//! transformation contract, the visibility+coverage composition
//! matrix, and the deterministic fixed fake probe through the public
//! `CapabilityProbe` trait.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code uses expect/unwrap/panic for direct assertions on the capability contract"
)]

use sysdhardener_core::{
    Capability, CapabilityProbe, CoverageQuality, EffectiveUid, FixedCapabilityProbe,
    ProcStatusCapabilityProbe, combine_visibility, parse_effective_uid, parse_status_visibility,
};

const ROOT_STATUS: &str = "Name:\tsystemd\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
const NONROOT_STATUS: &str =
    "Name:\tuser-proc\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
/// Real UID 0 but *effective* UID 1: the effective field is the
/// discriminator, never the real field.
const REAL_ROOT_EFFECTIVE_NONROOT: &str = "Uid:\t0\t1\t2\t3\n";

#[test]
fn root_status_parses_to_expected_root() {
    assert_eq!(
        parse_status_visibility(ROOT_STATUS),
        Capability::ExpectedRoot
    );
    let uid: EffectiveUid =
        parse_effective_uid(ROOT_STATUS).expect("root status parses to a typed effective UID");
    assert!(uid.is_root(), "effective UID 0 must classify as root");
    assert_eq!(uid.raw(), 0);
}

#[test]
fn nonroot_status_parses_to_degraded_non_root() {
    assert_eq!(
        parse_status_visibility(NONROOT_STATUS),
        Capability::DegradedNonRoot
    );
    let uid: EffectiveUid = parse_effective_uid(NONROOT_STATUS)
        .expect("non-root status parses to a typed effective UID");
    assert!(!uid.is_root());
    assert_eq!(uid.raw(), 1000);
}

#[test]
fn effective_field_not_real_field_is_the_discriminator() {
    assert_eq!(
        parse_status_visibility(REAL_ROOT_EFFECTIVE_NONROOT),
        Capability::DegradedNonRoot
    );
}

#[test]
fn from_capability_never_yields_complete_and_maps_unknown_nonroot_to_degraded() {
    // The exhaustive contract: capability alone can never produce
    // `CoverageQuality::Complete`; unknown/non-root visibility is
    // degraded; root alone yields Unknown (root does not imply
    // complete observation, only evidence can).
    assert_eq!(
        CoverageQuality::from_capability(Capability::ExpectedRoot),
        CoverageQuality::Unknown
    );
    assert_eq!(
        CoverageQuality::from_capability(Capability::DegradedNonRoot),
        CoverageQuality::Degraded
    );
    assert_eq!(
        CoverageQuality::from_capability(Capability::Unknown),
        CoverageQuality::Degraded
    );
}

#[test]
fn combine_visibility_full_matrix() {
    // ExpectedRoot preserves the evidence coverage value unchanged:
    // root never upgrades, never downgrades, and only the wire
    // envelope can carry Complete.
    assert_eq!(
        combine_visibility(Capability::ExpectedRoot, CoverageQuality::Complete),
        CoverageQuality::Complete
    );
    assert_eq!(
        combine_visibility(Capability::ExpectedRoot, CoverageQuality::Degraded),
        CoverageQuality::Degraded
    );
    assert_eq!(
        combine_visibility(Capability::ExpectedRoot, CoverageQuality::Unknown),
        CoverageQuality::Unknown
    );
    // DegradedNonRoot and Unknown capability always degrade the
    // result, even when the evidence claimed complete.
    for cap in [Capability::DegradedNonRoot, Capability::Unknown] {
        for evidence in [
            CoverageQuality::Complete,
            CoverageQuality::Degraded,
            CoverageQuality::Unknown,
        ] {
            assert_eq!(
                combine_visibility(cap, evidence),
                CoverageQuality::Degraded,
                "capability {cap:?} with evidence {evidence:?} must degrade"
            );
        }
    }
}

#[test]
fn fixed_fake_probe_reports_canned_capability_through_trait() {
    let root = FixedCapabilityProbe::new(Capability::ExpectedRoot);
    let nonroot = FixedCapabilityProbe::new(Capability::DegradedNonRoot);
    let unknown = FixedCapabilityProbe::new(Capability::Unknown);

    assert_eq!(root.visibility(), Capability::ExpectedRoot);
    assert_eq!(nonroot.visibility(), Capability::DegradedNonRoot);
    assert_eq!(unknown.visibility(), Capability::Unknown);
}

#[test]
fn real_probe_implements_trait_without_panicking() {
    let probe = ProcStatusCapabilityProbe;
    let visibility = probe.visibility();
    assert!(
        matches!(
            visibility,
            Capability::ExpectedRoot | Capability::DegradedNonRoot | Capability::Unknown
        ),
        "real probe returned {visibility:?}"
    );
}

#[test]
fn syscall_to_capabilities_maps_ptrace_family_correctly() {
    use sysdhardener_core::{LinuxCapability, syscall_to_capabilities};
    assert_eq!(
        syscall_to_capabilities("ptrace"),
        &[LinuxCapability::SysPtrace]
    );
    assert_eq!(
        syscall_to_capabilities("process_vm_readv"),
        &[LinuxCapability::SysPtrace]
    );
    assert_eq!(
        syscall_to_capabilities("process_vm_writev"),
        &[LinuxCapability::SysPtrace]
    );
}

#[test]
fn syscall_to_capabilities_maps_new_syscalls_and_capabilities_correctly() {
    use sysdhardener_core::{
        LinuxCapability, syscall_to_capabilities, syscall_to_inherent_capabilities,
    };

    assert_eq!(syscall_to_capabilities("mknod"), &[LinuxCapability::Mknod]);
    assert_eq!(
        syscall_to_capabilities("mknodat"),
        &[LinuxCapability::Mknod]
    );
    assert_eq!(
        syscall_to_capabilities("setrlimit"),
        &[LinuxCapability::SysResource]
    );
    assert_eq!(
        syscall_to_capabilities("bpf"),
        &[LinuxCapability::Bpf, LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_capabilities("perf_event_open"),
        &[LinuxCapability::Perfmon, LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_capabilities("chmod"),
        &[LinuxCapability::Fowner, LinuxCapability::Fsetid]
    );
    assert_eq!(
        syscall_to_capabilities("fchmod"),
        &[LinuxCapability::Fowner, LinuxCapability::Fsetid]
    );
    assert_eq!(
        syscall_to_capabilities("fchmodat"),
        &[LinuxCapability::Fowner, LinuxCapability::Fsetid]
    );
    assert_eq!(
        syscall_to_capabilities("sethostname"),
        &[LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_capabilities("lsetxattr"),
        &[
            LinuxCapability::Setfcap,
            LinuxCapability::MacOverride,
            LinuxCapability::MacAdmin,
        ]
    );
    assert_eq!(
        syscall_to_capabilities("fsetxattr"),
        &[
            LinuxCapability::Setfcap,
            LinuxCapability::MacOverride,
            LinuxCapability::MacAdmin,
        ]
    );
    assert_eq!(
        syscall_to_capabilities("openat2"),
        &[LinuxCapability::DacOverride, LinuxCapability::DacReadSearch]
    );
    assert_eq!(
        syscall_to_capabilities("readlinkat"),
        &[LinuxCapability::DacOverride, LinuxCapability::DacReadSearch]
    );
    assert_eq!(
        syscall_to_capabilities("faccessat"),
        &[LinuxCapability::DacOverride, LinuxCapability::DacReadSearch]
    );
    assert_eq!(
        syscall_to_capabilities("faccessat2"),
        &[LinuxCapability::DacOverride, LinuxCapability::DacReadSearch]
    );

    assert_eq!(
        syscall_to_inherent_capabilities("mknod"),
        &[LinuxCapability::Mknod]
    );
    assert_eq!(
        syscall_to_inherent_capabilities("mknodat"),
        &[LinuxCapability::Mknod]
    );
    assert_eq!(
        syscall_to_inherent_capabilities("bpf"),
        &[LinuxCapability::Bpf, LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_inherent_capabilities("perf_event_open"),
        &[LinuxCapability::Perfmon, LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_capabilities("seccomp"),
        &[LinuxCapability::SysAdmin]
    );
    assert_eq!(
        syscall_to_capabilities("io_uring_enter"),
        &[LinuxCapability::SysAdmin]
    );
    assert_eq!(syscall_to_capabilities("write"), &[]);
    assert_eq!(syscall_to_capabilities("stat"), &[]);
}
