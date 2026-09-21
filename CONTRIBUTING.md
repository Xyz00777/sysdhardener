# Contributing to sysdhardener

Thank you for your interest in contributing to **sysdhardener**! This document provides the guidelines, developer environment setup, coding standards, and verification requirements needed to contribute effectively.

---

## 1. Project Philosophy & Core Invariants

`sysdhardener` is an on-demand profiling and hardening recommendation engine for systemd services. When contributing, keep these foundational invariants in mind:

- **Recommendation Engine Only:** The tool derives evidence-based hardening recommendations; it **never applies** modifications to host unit files, system configurations, or running services.
- **Strictly Grounded (No Fabricated Facts):** All candidate directives and capability mappings must be grounded in verified authoritative sources (see [`docs/research.md`](docs/research.md)). The core engine must remain **distribution-agnostic** and never hardcode OS or kernel assumptions.
- **Two-View Output Contract:** Recommendations are presented as both a drop-in fragment (`hardening.conf`) starting with a single warning header and a detailed human-readable audit log (`findings.txt`).
- **Graceful Partial Failure:** Output sinks must be isolated; failure in one sink (e.g. read-only disk) must preserve all successful outputs.

---

## 2. Workspace Overview

The project is structured as a multi-crate Cargo workspace:

| Crate / Directory | Description |
| :--- | :--- |
| [`crates/sysdhardener-core`](crates/sysdhardener-core) | Pure, deterministic analysis engine, domain models, capability probes, version gate, and output sinks. |
| [`crates/sysdhardener-observer`](crates/sysdhardener-observer) | Live process observation engine using Linux `ptrace` (`PTRACE_TRACEME` and `PTRACE_SEIZE`). |
| [`crates/sysdhardener-wire-format`](crates/sysdhardener-wire-format) | Shared, zero-copy binary event structures exchanged between kernel eBPF and user space. |
| [`crates/sysdhardener-bpf-loader`](crates/sysdhardener-bpf-loader) | Aya-based eBPF program loader and ring-buffer bridge (`--features bpf-observe`). |
| [`crates/sysdhardener-ebpf`](crates/sysdhardener-ebpf) | In-kernel eBPF cgroup `sock_addr` tracing program. |
| [`crates/sysdhardener-cli`](crates/sysdhardener-cli) | Public binary CLI entry point (`sysdhardener observe`, `attach`, `analyze-fixture`). |
| [`docs/`](docs) | Architecture specifications (arc42), decision records, wire schemas, and reference environment validation. |
| [`scripts/`](scripts) | CI automation, source size checking, Nix validation, and VM provisioning scripts. |

---

## 3. Development Environment Setup

### Option A: Nix with direnv (Recommended)

The repository provides a pinned, reproducible development environment managed with Nix flakes:

```sh
# Clone the repository
git clone https://github.com/your-org/sysdhardener.git
cd sysdhardener

# Allow direnv to load the pinned flake shell
direnv allow
```

This automatically provisions Rust, Cargo, `clippy`, `rustfmt`, `cargo-deny`, `bpf-linker`, and all build dependencies.

### Option B: Standard Toolchain

If you prefer using your host's toolchain, ensure you have:
- **Rust:** Version 1.85 or newer.
- **Tools:** `cargo`, `rustfmt`, `clippy`, and `cargo-deny`.

---

## 4. Mandatory Development Rules

To maintain code quality and architectural integrity, the repository enforces several automated checks:

### A. The 250-Pure-LOC Ceiling

Every Rust source file (`.rs`) in the workspace must have **at most 250 pure lines of code**.
- "Pure LOC" is defined as any physical line that is non-blank and does not start with a comment (`//`, `/*`, `*`, `*/`).
- Enforced automatically by [`scripts/check-source-size.sh`](scripts/check-source-size.sh).
- **Rule of thumb:** If a module approaches the ceiling, decompose it into focused submodules with explicit boundaries.

### B. Nix Single-Source-of-Truth

All development dependencies must be declared in exactly one place: [`nix/dependencies.nix`](nix/dependencies.nix).
- Do not duplicate package declarations in `flake.nix` or `default.nix`.
- Enforced by [`scripts/check-nix-single-source.sh`](scripts/check-nix-single-source.sh).

### C. Formatting and Clippy

All code must format cleanly with standard `rustfmt` and pass `clippy` with zero warnings:
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

---

## 5. Testing Guidelines

We prioritize robust testing across multiple layers:

1. **Unit Tests:** Placed within each crate's `src/` modules for isolated logic.
2. **Integration Tests:** Located in `tests/` directories testing end-to-end flows.
3. **Contract & Adversarial Tests:** Found in `crates/sysdhardener-core/tests/` to lock boundary conditions:
   - Schema rejection and malformed JSON matrices.
   - Negative tests verifying forbidden strings (e.g. no hardcoded distro versions in records).
   - Link and documentation claims contract ([`tests/readme_contract.rs`](crates/sysdhardener-core/tests/readme_contract.rs)).

Run tests across the workspace:
```sh
# Run standard workspace tests
cargo test

# Run tests including eBPF loader features
cargo test --features bpf-observe
```

---

## 6. Pre-Submission Checklist (The 7 CI Gates)

Before opening a pull request or submitting changes, run the local CI verification script:

```sh
./scripts/ci.sh
```

This script verifies all 7 project gates in sequence:
1. `cargo fmt --check` (code formatting)
2. `cargo clippy --all-targets -- -D warnings` (strict lints)
3. `cargo test --all-targets` (test suite execution)
4. `scripts/check-source-size.sh` (250 pure-LOC ceiling)
5. `scripts/check-nix-single-source.sh` (Nix dependency single source)
6. `cargo deny check` (security advisories, licenses, and banned crates)
7. `scripts/check-ci-single-source.sh` (GitHub Actions workflow consistency)

If all 7 gates pass, your contribution is ready for review!

---

## 7. Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` A new feature or recommendation directive.
- `fix:` A bug fix in analysis or observation.
- `docs:` Documentation updates.
- `test:` Adding or updating tests.
- `refactor:` Code refactoring that neither fixes a bug nor adds a feature.
- `chore:` Tooling, dependency updates, or script adjustments.

Keep commit messages concise, technical, and focused on the *what* and *why*.
