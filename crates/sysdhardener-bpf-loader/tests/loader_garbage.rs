//! Confirm the loader fails cleanly on garbage bytes WITHOUT root,
//! before any attach — proving the error path is testable in CI.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use sysdhardener_bpf_loader::observe_cgroup_events;

#[test]
fn garbage_object_loads_fail_cleanly_without_root() {
    let garbage: &[u8] = b"this is not a valid eBPF object";
    // The LOAD failure (garbage bytes) happens before any cgroup
    // attach, so the fd is never dereferenced. `/dev/null` is
    // portable and always openable, unlike `/sys/fs/cgroup` which may
    // be absent in a containerized CI.
    let cg = std::fs::File::open("/dev/null").expect("/dev/null readable");
    let result = observe_cgroup_events(garbage, &cg, 10);
    assert!(result.is_err(), "garbage object must fail to load");
}
