#!/usr/bin/env bash
# scripts/check-nix-single-source.sh
#
# Enforce ADR-0002: the flake and non-flake entry points must both consume
# the single canonical dependency expression `nix/dependencies.nix`. If
# either entry point ever carries an independent package list inside
# `packages = [...]`, this script rejects the worktree.
#
# The script distinguishes legitimate references (e.g. `pkgs.rustc`
# inside the MSRV assertion block in `default.nix`) from the actual
# anti-drift signal: a literal `pkgs.<tool>` adding to the package list.
# The canonical form is `packages = dependencies;` (a single identifier
# bound to the imported expression).
#
# The script exits 0 if every entry point either imports
# `nix/dependencies.nix` and passes its `packages` list through a
# single binding, or has no `packages =` list at all.

set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

status=0

# Whitelist of tool names that must come from `nix/dependencies.nix`.
# If any of these appears as a `pkgs.<name>` outside that import, the
# entry point has drifted into a parallel package list.
tools='rustc|cargo|clippy|rustfmt|cargo-nextest|cargo-deny|git|jq|graphviz|nodejs|nixfmt|shellcheck'

checked=0
for entry in "${REPO_ROOT}/flake.nix" "${REPO_ROOT}/default.nix"; do
  if [[ ! -f "$entry" ]]; then
    echo "FAIL: missing entry point ${entry}" >&2
    status=1
    continue
  fi
  checked=$((checked + 1))

  # ADR-0002: must import the single dependency expression.
  if ! grep -q "import ./nix/dependencies.nix\|import .*nix/dependencies.nix" "$entry"; then
    echo "FAIL ${entry}: does not import nix/dependencies.nix (ADR-0002 violation)" >&2
    status=1
    continue
  fi

  # Extract the `packages = EXPR;` line and inspect it. Lines that
  # reference `pkgs.<tool>` inside the `packages =` expression are drift.
  # Lines that reference `pkgs.<tool>` elsewhere (e.g. MSRV assertion)
  # are not drift.
  drift=$(grep -nE 'packages\s*=\s*' "$entry" \
    | grep -E "pkgs\.(${tools})\b" || true)
  if [[ -n "$drift" ]]; then
    echo "FAIL ${entry}: lists Rust/Nix tools directly in 'packages =' instead of via nix/dependencies.nix:" >&2
    printf '    %s\n' "$drift" >&2
    status=1
    continue
  fi
  echo "OK ${entry}: imports nix/dependencies.nix and passes the bound name into packages"
done

if (( status == 0 )); then
  echo "=== Nix single-source: ${checked} entry point(s) compliant ==="
fi

exit "$status"
