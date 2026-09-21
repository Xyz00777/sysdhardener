//! E2E test for `sysdhardener attach`: the independent-observer
//! interposition. The target is spawned by the test (so it is a
//! descendant, allowed by Yama `ptrace_scope=1`), then `attach` is
//! driven against it via the library API. A sibling process would be
//! blocked by Yama unless run as root (root is the expected production
//! execution mode; this test runs same-UID descendant).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use std::process::Command;

use sysdhardener_observer::observe_pid;

/// Path to the repeating-syscall target binary.
fn target_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_repeating_target"))
}

#[test]
fn attach_to_descendant_captures_its_syscalls() {
    // The target is spawned by this test, so it is our descendant:
    // Yama ptrace_scope=1 allows attaching to descendants. It loops
    // doing socket/bind for 3 seconds, so the attach (started after
    // spawn) still has syscalls to capture.
    let mut target = Command::new(target_binary())
        .spawn()
        .expect("target must spawn");
    std::thread::sleep(std::time::Duration::from_millis(300));

    let pid = i32::try_from(target.id()).expect("target pid fits in i32");
    let events = observe_pid(pid).expect("attach to descendant must succeed");
    let _ = target.wait();

    assert!(
        !events.is_empty(),
        "attached observer must capture the target's syscalls"
    );
    let inet_seen = events
        .iter()
        .any(|e| e.args().starts_with("socket") && e.args().contains("family=inet"));
    assert!(inet_seen, "attached capture must include an inet socket");
    let has_cgroup = events.iter().any(|e| e.cgroup().is_some());
    assert!(
        has_cgroup,
        "attached capture must carry cgroup attribution (the production observer's unit)"
    );
}

#[test]
fn systemd_unit_from_cgroup_maps_service_paths() {
    use sysdhardener_observer::systemd_unit_from_cgroup;

    assert_eq!(
        systemd_unit_from_cgroup("/system.slice/nginx.service"),
        Some("nginx.service")
    );
    // A user-managed scope still sits under the user-manager service
    // (user@1000.service); that is the governing .service unit.
    assert_eq!(
        systemd_unit_from_cgroup(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo-bar.scope"
        ),
        Some("user@1000.service")
    );
    assert_eq!(
        systemd_unit_from_cgroup(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/custom-app.service"
        ),
        Some("custom-app.service"),
        "user service nested under user manager resolves to leafmost service"
    );
    assert_eq!(
        systemd_unit_from_cgroup("/system.slice/sshd.service/main"),
        Some("sshd.service"),
        "the .service component is found anywhere in the path"
    );
    assert_eq!(
        systemd_unit_from_cgroup("/system.slice/nginx.service/"),
        Some("nginx.service")
    );
    assert_eq!(
        systemd_unit_from_cgroup("/system.slice/nginx.service///"),
        Some("nginx.service")
    );
    assert_eq!(systemd_unit_from_cgroup("/"), None);
}

#[test]
fn invalid_pid_is_rejected_safely() {
    use sysdhardener_observer::{ObserveError, observe_pid};

    assert!(matches!(observe_pid(0), Err(ObserveError::Wait(_))));
    assert!(matches!(observe_pid(-1), Err(ObserveError::Wait(_))));
}
