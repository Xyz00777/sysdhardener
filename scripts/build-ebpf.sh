#!/usr/bin/env bash
# scripts/build-ebpf.sh
#
# Build the in-kernel eBPF program (`crates/sysdhardener-ebpf`) into a
# BPF ELF object the user-space loader (`crates/sysdhardener-bpf-loader`)
# consumes.
#
# The eBPF crate is deliberately EXCLUDED from the Cargo workspace (see
# the root Cargo.toml): it needs a nightly toolchain
# (`#![feature(asm_experimental_arch)]`), the `bpfel-unknown-none`
# target (no prebuilt std artifacts — built via `-Z build-std=core` +
# rust-src), and `bpf-linker`. The nightly's LLVM version must match
# the LLVM feature nixpkgs' bpf-linker was built with (`llvm-21`);
# nightly-2026-09-07 (LLVM 23.1.1) is the verified pairing with
# bpf-linker 0.11.1.
#
# Usage: bash scripts/build-ebpf.sh   (from the repository root)
# Output: crates/sysdhardener-ebpf/target/bpfel-unknown-none/release/sysdhardener-ebpf
#
# Requires: rustup (nightly + rust-src) and bpf-linker 0.11.1 on PATH.
# The Nix dev shell supplies both pinned tools.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EBPF_CRATE="${REPO_ROOT}/crates/sysdhardener-ebpf"

# The nightly whose LLVM matches the pinned upstream bpf-linker release.
NIGHTLY="${NIGHTLY:-nightly-2026-09-07}"
BPF_LINKER_VERSION="0.11.1"

command -v bpf-linker >/dev/null 2>&1 || {
  echo "FAIL: bpf-linker not on PATH" >&2
  echo "  enter the Nix dev shell or install bpf-linker ${BPF_LINKER_VERSION}" >&2
  exit 1
}

LINKER_VERSION="$(bpf-linker --version | awk '{print $2}')"
if [[ "${LINKER_VERSION}" != "${BPF_LINKER_VERSION}" ]]; then
  echo "FAIL: expected bpf-linker ${BPF_LINKER_VERSION}, found ${LINKER_VERSION}" >&2
  exit 1
fi

echo "==> rustup toolchain: ${NIGHTLY}"
rustup toolchain install "${NIGHTLY}" --profile minimal --component rust-src

RUSTC_LLVM="$(rustc +"${NIGHTLY}" --version --verbose | awk '/^LLVM version:/ {print $3}')"
if [[ "${RUSTC_LLVM}" != 23.* ]]; then
  echo "FAIL: expected Rust LLVM 23.x, found ${RUSTC_LLVM}" >&2
  exit 1
fi
echo "==> Rust LLVM: ${RUSTC_LLVM}; bpf-linker: ${LINKER_VERSION} (LLVM 23)"

echo "==> building sysdhardener-ebpf (bpfel-unknown-none, build-std=core)"
(
  cd "${EBPF_CRATE}"
  # The crate's `.cargo/config.toml` supplies `--btf` + `-C debuginfo=1`
  # (bpf-linker generates `.BTF` from DWARF; without full debuginfo the
  # loader rejects the object with ParseError::NoBTF).
  cargo +"${NIGHTLY}" build \
    --release \
    --target bpfel-unknown-none \
    -Z build-std=core
)

OUT="${EBPF_CRATE}/target/bpfel-unknown-none/release/sysdhardener-ebpf"
echo "==> artifact: ${OUT}"
file "${OUT}"
