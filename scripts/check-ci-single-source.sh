#!/usr/bin/env bash
# scripts/check-ci-single-source.sh
#
# Enforce that the GitHub Actions workflow runs `scripts/ci.sh` as the
# single source of truth for the local gates (fmt, clippy, test,
# source-size, nix-single-source). If the workflow ever re-inlines
# those steps (or drops the ci.sh call), local and CI can drift; this
# script rejects that.
#
# Exit 0 when the workflow calls ci.sh; exit 1 otherwise.

set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
WORKFLOW="${REPO_ROOT}/.github/workflows/ci.yml"

if [[ ! -f "$WORKFLOW" ]]; then
  echo "FAIL: missing ${WORKFLOW}" >&2
  exit 1
fi

if ! grep -q "scripts/ci.sh" "$WORKFLOW"; then
  echo "FAIL: ${WORKFLOW} must run scripts/ci.sh (single source of truth for the local gates)" >&2
  exit 1
fi

echo "OK ${WORKFLOW}: runs scripts/ci.sh"
