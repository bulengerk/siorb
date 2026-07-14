#!/usr/bin/env python3
"""Render and validate the release Homebrew formula from immutable subjects."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--aarch64", type=pathlib.Path, required=True)
    parser.add_argument("--x86-64", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        parser.error("version must be stable MAJOR.MINOR.PATCH")
    for archive in (args.aarch64, args.x86_64):
        if not archive.is_file() or archive.is_symlink():
            parser.error(f"archive must be a regular non-symlink file: {archive}")
    if not args.base_url.startswith("https://"):
        parser.error("base URL must use HTTPS")

    root = pathlib.Path(__file__).resolve().parents[2]
    template = (root / "packaging/macos/homebrew/siorb.rb.in").read_text(encoding="utf-8")
    values = {
        "@VERSION@": args.version,
        "@AARCH64_URL@": f"{args.base_url.rstrip('/')}/{args.aarch64.name}",
        "@AARCH64_SHA256@": digest(args.aarch64),
        "@X86_64_URL@": f"{args.base_url.rstrip('/')}/{args.x86_64.name}",
        "@X86_64_SHA256@": digest(args.x86_64),
    }
    for marker, value in values.items():
        template = template.replace(marker, value)
    if re.search(r"@[A-Z0-9_]+@", template):
        parser.error("unexpanded marker remains in formula")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.is_symlink():
        parser.error("refusing to replace a symlink output")
    args.output.write_text(template, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
