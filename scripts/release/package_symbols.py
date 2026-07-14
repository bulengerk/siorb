#!/usr/bin/env python3
"""Create a deterministic ZIP containing retained native debug symbols."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shutil
import stat
import time
import zipfile

SAFE = re.compile(r"^[0-9A-Za-z_.-]+$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--symbols", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not SAFE.fullmatch(args.target) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", args.version):
        parser.error("unsafe version or target")
    source = args.symbols
    if source.is_symlink() or not source.exists():
        parser.error("symbols path must exist and not be a symlink")
    entries = [source] if source.is_file() else sorted(source.rglob("*"))
    for path in entries:
        if path.is_symlink():
            parser.error(f"symbols contain a symlink: {path}")
    files = [path for path in entries if path.is_file()]
    if not files:
        parser.error("symbols path contains no files")
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError as error:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from error
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"siorb-{args.version}-{args.target}-symbols.zip"
    if output.is_symlink():
        parser.error("refusing to replace a symlink output")
    base = source.parent
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            name = path.relative_to(base).as_posix()
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with path.open("rb") as source_handle, archive.open(info, "w") as destination:
                shutil.copyfileobj(source_handle, destination, length=1024 * 1024)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
