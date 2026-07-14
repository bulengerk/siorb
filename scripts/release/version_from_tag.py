#!/usr/bin/env python3
"""Verify a release tag against workspace metadata and reviewed changelog."""

from __future__ import annotations

import argparse
import pathlib
import re
import tomllib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--github-output", type=pathlib.Path)
    args = parser.parse_args()
    match = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)", args.tag)
    if not match:
        parser.error("release tag must be vMAJOR.MINOR.PATCH with optional SemVer prerelease")
    version = match.group(1)
    root = pathlib.Path(__file__).resolve().parents[2]
    cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    actual = str(cargo["workspace"]["package"]["version"])
    if actual != version:
        parser.error(f"tag version {version} does not match workspace version {actual}")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?\s*$", changelog, re.MULTILINE):
        parser.error(f"CHANGELOG.md has no release section for {version}")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"version={version}\n")
            handle.write(f"prerelease={'true' if '-' in version else 'false'}\n")
    else:
        print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
