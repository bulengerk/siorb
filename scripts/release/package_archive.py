#!/usr/bin/env python3
"""Create a deterministic platform archive from an already-built CLI binary."""

from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import re
import shutil
import stat
import tarfile
import time
import zipfile

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
TARGET = re.compile(r"^[0-9A-Za-z_.-]+$")


def source_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        value = int(raw)
    except ValueError as error:
        raise SystemExit("SOURCE_DATE_EPOCH must be a non-negative integer") from error
    if value < 0:
        raise SystemExit("SOURCE_DATE_EPOCH must be a non-negative integer")
    return value


def checked_file(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"{label} must be a regular non-symlink file: {path}")
    return path


def inputs(binary: pathlib.Path, readme: pathlib.Path, license_file: pathlib.Path, windows: bool):
    return [
        ("siorb.exe" if windows else "siorb", checked_file(binary, "binary"), 0o755),
        ("README.md", checked_file(readme, "README"), 0o644),
        ("LICENSE", checked_file(license_file, "license"), 0o644),
    ]


def write_zip(output: pathlib.Path, files, epoch: int) -> None:
    # ZIP cannot represent timestamps before 1980-01-01.
    stamp = time.gmtime(max(epoch, 315532800))[:6]
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, path, mode in files:
            info = zipfile.ZipInfo(name, stamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | mode) << 16
            with path.open("rb") as source, archive.open(info, "w") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)


def write_tar_gz(output: pathlib.Path, files, epoch: int) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, path, mode in files:
                    info = tarfile.TarInfo(name)
                    info.size = path.stat().st_size
                    info.mode = mode
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    with path.open("rb") as source:
                        archive.addfile(info, source)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--readme", type=pathlib.Path)
    parser.add_argument("--license", dest="license_file", type=pathlib.Path)
    args = parser.parse_args()
    if not SEMVER.fullmatch(args.version):
        parser.error("version must be MAJOR.MINOR.PATCH with an optional SemVer prerelease")
    if not TARGET.fullmatch(args.target):
        parser.error("target contains unsafe characters")

    root = pathlib.Path(__file__).resolve().parents[2]
    readme = args.readme or root / "README.md"
    license_file = args.license_file or root / "LICENSE"
    windows = "windows" in args.target
    files = inputs(args.binary, readme, license_file, windows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    extension = "zip" if windows else "tar.gz"
    output = args.output_dir / f"siorb-{args.version}-{args.target}.{extension}"
    if output.exists() and output.is_symlink():
        parser.error("refusing to replace a symlink output")
    epoch = source_epoch()
    if windows:
        write_zip(output, files, epoch)
    else:
        write_tar_gz(output, files, epoch)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
