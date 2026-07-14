#!/usr/bin/env python3
"""Render WinGet multipart manifests from a reviewed release ZIP."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MARKER = re.compile(r"@[A-Z0-9_]+@")


def sha256(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest().upper()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--x86-64", type=pathlib.Path, required=True)
    parser.add_argument("--arm64", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not VERSION.fullmatch(args.version):
        parser.error("version must be stable MAJOR.MINOR.PATCH")
    if not args.base_url.startswith("https://"):
        parser.error("base URL must use HTTPS")
    for architecture, archive in (("x86-64", args.x86_64), ("ARM64", args.arm64)):
        if not archive.is_file() or archive.is_symlink():
            parser.error(f"{architecture} ZIP must be a regular non-symlink file")

    root = pathlib.Path(__file__).resolve().parents[2]
    source = root / "packaging/windows/winget"
    values = {
        "@VERSION@": args.version,
        "@X86_64_URL@": f"{args.base_url.rstrip('/')}/{args.x86_64.name}",
        "@X86_64_SHA256@": sha256(args.x86_64),
        "@ARM64_URL@": f"{args.base_url.rstrip('/')}/{args.arm64.name}",
        "@ARM64_SHA256@": sha256(args.arm64),
    }
    if args.output_dir.is_symlink():
        parser.error("output directory cannot be a symlink")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for template_path in sorted(source.glob("*.yaml.in")):
        rendered = template_path.read_text(encoding="utf-8")
        for marker, value in values.items():
            rendered = rendered.replace(marker, value)
        unknown = MARKER.search(rendered)
        if unknown:
            parser.error(f"unexpanded marker {unknown.group()} in {template_path.name}")
        output = args.output_dir / template_path.name.removesuffix(".in")
        if output.is_symlink():
            parser.error(f"refusing to replace a symlink output: {output}")
        output.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
