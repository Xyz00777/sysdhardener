{ pkgs, bpfLinker }:

# Single canonical dependency expression consumed by both the flake
# (`flake.nix`) and the non-flake (`default.nix`) dev shell. Any new tool
# must land here.
with pkgs;
[
  # Repository and artifact inspection.
  git
  jq

  # Documentation and architecture diagrams.
  graphviz
  nodejs

  # Local syntax and shell validation.
  nixfmt
  shellcheck

  # Rust and eBPF toolchains. The locked nixpkgs (nixos-26.05) ships rustc 1.97.1,
  # which is greater than the workspace MSRV 1.87; the dev shell uses
  # the same compiler as the workspace build (no rustup channel
  # override). The eBPF build uses rustup for nightly-2026-09-07 and
  # the pinned upstream bpf-linker 0.11.1 release, built for LLVM 23.1.1.
  # `cargo-nextest` and `cargo-deny` are used for tests and linting.
  rustc
  cargo
  clippy
  rustfmt
  rustup
  bpfLinker
  cargo-nextest
  cargo-deny
]
