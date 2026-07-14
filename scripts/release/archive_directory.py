#!/usr/bin/env python3
"""Create a deterministic ZIP from a metadata directory."""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import stat
import time
import zipfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not args.directory.is_dir() or args.directory.is_symlink():
        parser.error("directory must be a real directory")
    directory = args.directory.resolve()
    output_path = args.output.resolve()
    if output_path == directory or directory in output_path.parents:
        parser.error("output must be outside the input directory")
    entries = sorted(args.directory.rglob("*"))
    for path in entries:
        if path.is_symlink():
            parser.error(f"directory contains a symlink: {path}")
    files = [path for path in entries if path.is_file()]
    if not files:
        parser.error("directory contains no files")
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError as error:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from error
    if epoch < 0:
        parser.error("SOURCE_DATE_EPOCH cannot be negative")
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.is_symlink():
        parser.error("refusing to replace a symlink output")
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(args.directory).as_posix(), stamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open("rb") as source, archive.open(info, "w") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
