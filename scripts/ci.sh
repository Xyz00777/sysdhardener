#!/usr/bin/env bash
# scripts/ci.sh
#
# Local CI gate: runs every quality gate the repository enforces, in
# dependency order, and fails on the first violation. This is the
# same gate set the GitHub Actions workflow (`.github/workflows/ci.yml`)
# runs; the workflow delegates cargo-deny to its dedicated action job.
#
# Gates:
#   1. cargo fmt --check
#   2. cargo clippy --workspace --all-targets --all-features -D warnings
#   3. cargo test --workspace --all-features
#   4. scripts/check-source-size.sh (250 pure-LOC ceiling)
#   5. scripts/check-nix-single-source.sh
#   6. cargo deny check (or SKIP_CARGO_DENY=1 when delegated to the action job)
#   7. scripts/check-ci-single-source.sh (workflow must call ci.sh)
#
# Usage: bash scripts/ci.sh   (from the repository root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

fail() {
  echo "CI FAIL: $1" >&2
  exit 1
}

echo "==> [1/7] cargo fmt --check"
cargo fmt --all --check || fail "rustfmt"

echo "==> [2/7] cargo clippy (all targets, all features, -D warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings || fail "clippy"

echo "==> [3/7] cargo test (workspace, all features)"
cargo test --workspace --all-features || fail "tests"

echo "==> [4/7] source-size ceiling"
bash scripts/check-source-size.sh || fail "source-size"

echo "==> [5/7] nix single-source"
bash scripts/check-nix-single-source.sh || fail "nix-single-source"

if [[ "${SKIP_CARGO_DENY:-0}" == "1" ]]; then
  echo "==> [6/7] cargo deny (handled by cargo-deny job)"
else
  echo "==> [6/7] cargo deny"
  cargo deny check || fail "cargo-deny"
fi

echo "==> [7/7] ci single-source (workflow must call ci.sh)"
bash scripts/check-ci-single-source.sh || fail "ci-single-source"

echo "CI OK: all gates passed"
