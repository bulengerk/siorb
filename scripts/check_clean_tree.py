#!/usr/bin/env python3
"""Require generated output to leave no tracked or untracked repository changes."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="optional repository paths to check")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    command = ["git", "status", "--porcelain=v1", "--untracked-files=all"]
    if args.paths:
        command.extend(["--", *args.paths])
    result = subprocess.run(command, cwd=root, check=True, stdout=subprocess.PIPE)
    if result.stdout:
        sys.stderr.write("generated output is stale or untracked:\n")
        sys.stderr.write(result.stdout.decode("utf-8", errors="replace"))
        sys.stderr.write("regenerate the files and commit the complete deterministic output\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
