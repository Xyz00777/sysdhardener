#!/usr/bin/env bash
# scripts/check-source-size.sh
#
# Enforce the project-wide 250-pure-LOC ceiling on every project `.rs` file.
# "Pure LOC" is defined in the implementation plan (Scope section): every
# physical line that is (a) non-blank after whitespace AND (b) whose first
# non-whitespace character is NOT `//`, `/*`, `*`, or `*/`. Brace-only and
# attribute lines count (they fail the comment test and pass the
# non-blank test).
#
# Exit 0 when every project .rs file is at or below 250; exit 1 otherwise.
# The script is the only size gate; the cargo workspace does not encode it
# as a lint, so the script is the source of truth.
#
# Usage:
#   scripts/check-source-size.sh [REPO_ROOT]
# Defaults REPO_ROOT to the parent of this script's directory.

set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
CEILING="${PURE_LOC_CEILING:-250}"

if ! [[ "$CEILING" =~ ^[0-9]+$ ]]; then
  echo "internal: PURE_LOC_CEILING must be a non-negative integer" >&2
  exit 2
fi

# Per-line test using awk. A line counts iff:
#   - it contains at least one non-whitespace character, AND
#   - that first non-whitespace character is NOT one of: /  *  (with the
#     opening forms `//`, `/*`, `*`, or closing `*/`).
# Brace-only lines (`}`, `{`) and attribute lines (`#[...]`) DO count.
count_pure_loc() {
  awk '
    {
      # Strip leading whitespace.
      sub(/^[[:space:]]+/, "")
      # Empty line after stripping: not counted.
      if ($0 == "") { next }
      # First non-whitespace character.
      first = substr($0, 1, 1)
      if (first == "/") {
        # `//` or `/*` (single-line block start) is a comment, skip.
        next
      }
      if (first == "*") {
        # `*` continuation or `*/` close is a comment, skip.
        next
      }
      count++
    }
    END { print count + 0 }
  ' "$1"
}

status=0
checked=0
failed=0

# Iterate over project .rs files only (skip target/, .git/, .direnv/,
# node_modules/, etc.) using find to remain pure shell.
while IFS= read -r -d '' file; do
  checked=$((checked + 1))
  loc=$(count_pure_loc "$file")
  if (( loc > CEILING )); then
    echo "FAIL ${file}: ${loc} pure-LOC > ceiling ${CEILING}" >&2
    failed=$((failed + 1))
    status=1
  fi
done < <(find "$REPO_ROOT" \
  \( -path "$REPO_ROOT/target" -o \
     -path "$REPO_ROOT/.git" -o \
     -path "$REPO_ROOT/.direnv" -o \
     -path "$REPO_ROOT/.codegraph" -o \
     -path "$REPO_ROOT/node_modules" \) -prune -o \
  -type f -name '*.rs' -print0)

if (( status == 0 )); then
  echo "OK ${checked} project .rs file(s) all <= ${CEILING} pure-LOC"
else
  echo "${failed} of ${checked} .rs file(s) exceed the ${CEILING} pure-LOC ceiling" >&2
fi

exit "$status"
