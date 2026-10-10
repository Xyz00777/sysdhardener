#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path


CLI_MANIFEST = "crates/sysdhardener-cli/Cargo.toml"
CHANGELOG = "CHANGELOG.md"
STABLE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def package_version(manifest: bytes) -> str:
    package = tomllib.loads(manifest.decode("utf-8"))["package"]
    version = package["version"]
    if not isinstance(version, str) or STABLE_VERSION.fullmatch(version) is None:
        raise ValueError("CLI package version must be a stable MAJOR.MINOR.PATCH version")
    return version


def version_at(ref: str) -> str:
    contents = subprocess.check_output(
        ["git", "show", f"{ref}:{CLI_MANIFEST}"], text=False
    )
    return package_version(contents)


def main() -> int:
    base_ref = os.environ.get("RELEASE_BASE_REF")
    if not base_ref:
        pull_request_base = os.environ.get("GITHUB_BASE_REF")
        if pull_request_base:
            base_ref = f"origin/{pull_request_base}"
    if not base_ref:
        print("Set RELEASE_BASE_REF or GITHUB_BASE_REF to identify the base commit", file=sys.stderr)
        return 2

    base = base_ref
    try:
        previous = version_at(base)
        current = package_version(Path(CLI_MANIFEST).read_bytes())
        if tuple(map(int, current.split("."))) <= tuple(map(int, previous.split("."))):
            raise ValueError(
                f"CLI version {current} must be greater than {previous} on {base}"
            )

        changelog = Path(CHANGELOG).read_text(encoding="utf-8")
        heading = f"## [{current}]"
        lines = changelog.splitlines()
        try:
            start = lines.index(heading) + 1
        except ValueError as error:
            raise ValueError(f"{CHANGELOG} must contain the heading '{heading}'") from error

        entry: list[str] = []
        for line in lines[start:]:
            if line.startswith("## "):
                break
            entry.append(line)
        if not any(line.strip() and not line.lstrip().startswith("<!--") for line in entry):
            raise ValueError(f"{CHANGELOG} entry for {current} must include release notes")

        changed = subprocess.run(
            ["git", "diff", "--quiet", base, "--", CHANGELOG],
            check=False,
        ).returncode
        if changed == 0 and subprocess.run(
            ["git", "ls-files", "--error-unmatch", CHANGELOG],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode != 0:
            changed = 1
        if changed == 0:
            raise ValueError(f"{CHANGELOG} must be updated in the pull request")
        if changed != 1:
            raise ValueError("could not determine whether CHANGELOG.md changed in this pull request")

    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Release metadata check failed: {error}", file=sys.stderr)
        return 1

    print(f"Release metadata OK: {previous} -> {current}, with a {CHANGELOG} entry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
