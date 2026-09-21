//! Confirm the real eBPF object (built by `scripts/build-ebpf.sh`)
//! parses correctly in the user-space loader via `Ebpf::load`.
//!
//! The loader needs kernel BTF + privileges (root/`CAP_BPF`) to resolve
//! the object's BTF maps, so this test is environment gated: it skips
//! when the object is absent or the environment cannot load it, and it
//! asserts the full program/map surface when the load succeeds. The
//! reference root/systemd host exercises the real path; the skip avoids
//! failing CI that lacks privileges.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests use expect/unwrap/panic for direct assertions on the boundary contract"
)]

use aya::Ebpf;

/// Path to the built BPF ELF (see `scripts/build-ebpf.sh`).
const OBJECT_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sysdhardener-ebpf/target/bpfel-unknown-none/release/sysdhardener-ebpf"
);

#[test]
fn shipped_ebpf_object_parses_in_the_loader() {
    if !std::path::Path::new(OBJECT_PATH).exists() {
        eprintln!("SKIP: {OBJECT_PATH} absent (run scripts/build-ebpf.sh)");
        return;
    }
    let bytes = std::fs::read(OBJECT_PATH).expect("built eBPF object readable");
    let bpf = match Ebpf::load(&bytes) {
        Ok(bpf) => bpf,
        // The environment cannot satisfy the loader's kernel
        // dependencies (BTF map loading needs root/CAP_BPF). The
        // reference root/systemd host exercises this path; here it is
        // a skip, not a failure.
        Err(aya::EbpfError::ParseError(aya_obj::ParseError::NoBTF)) => {
            eprintln!("SKIP: kernel BTF resolution unavailable (NoBTF)");
            return;
        }
        // The object parsed (BTF + relocations OK); the map create
        // failed on host policy (`unprivileged_bpf_disabled=2` or a
        // seccomp/cgroup restriction). The reference root host
        // exercises the real path; here it is a skip, not a failure.
        Err(aya::EbpfError::MapError(aya::maps::MapError::CreateError { .. })) => {
            eprintln!("SKIP: BPF map creation denied by host policy (EPERM)");
            return;
        }
        Err(other) => panic!("loader must parse the shipped eBPF object: {other:?}"),
    };
    for name in [
        "bind4", "bind6", "connect4", "connect6", "sendmsg4", "sendmsg6", "recvmsg4", "recvmsg6",
    ] {
        assert!(
            bpf.program(name).is_some(),
            "eBPF object must carry program {name}"
        );
    }
    assert!(
        bpf.map("EVENTS").is_some(),
        "eBPF object must carry the EVENTS ring-buffer map"
    );
}
