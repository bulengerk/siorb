#!/usr/bin/env python3
"""Generate a deterministic SHA-256 manifest for release files."""

from __future__ import annotations

import argparse
import hashlib
import pathlib


def hash_file(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.directory.is_symlink():
        parser.error("directory cannot be a symlink")
    directory = args.directory.resolve()
    if not directory.is_dir():
        parser.error("directory does not exist")
    output = args.output.resolve()
    if args.output.is_symlink():
        parser.error("refusing to replace a symlink checksum output")
    files = []
    for path in sorted(directory.rglob("*")):
        if path.resolve() == output:
            continue
        if path.is_symlink():
            parser.error(f"release directory contains a symlink: {path}")
        if path.is_file():
            files.append(path)
    if not files:
        parser.error("release directory has no files")
    lines = [f"{hash_file(path)}  {path.relative_to(directory).as_posix()}\n" for path in files]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(lines), encoding="ascii", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
