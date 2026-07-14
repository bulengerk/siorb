#!/usr/bin/env python3
"""Extract one reviewed release section from CHANGELOG.md."""

from __future__ import annotations

import argparse
import pathlib
import re


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[2]
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = re.compile(rf"^## \[{re.escape(args.version)}\](?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?\s*$", re.MULTILINE)
    match = heading.search(text)
    if not match:
        parser.error(f"release section {args.version} not found")
    next_heading = re.search(r"^## \[", text[match.end() :], re.MULTILINE)
    end = match.end() + next_heading.start() if next_heading else len(text)
    body = text[match.end() : end].strip()
    if not body:
        parser.error("release notes section is empty")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(f"# Siorb {args.version}\n\n{body}\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
