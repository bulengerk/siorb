#!/usr/bin/env python3
"""Safely extract a release catalog ZIP into a new static-mirror directory."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import stat
import zipfile

MAX_FILES = 10_000
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024


def safe_member(name: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(name)
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or any(part in {"", "."} for part in path.parts)
    ):
        raise ValueError(f"unsafe catalog archive member: {name}")
    return path


def extract(archive_path: pathlib.Path, output: pathlib.Path) -> None:
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("archive must be a regular non-symlink file")
    if output.exists() or output.is_symlink():
        raise ValueError("output must not already exist")

    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_FILES:
            raise ValueError("catalog archive has an invalid file count")
        if sum(entry.file_size for entry in entries) > MAX_TOTAL_SIZE:
            raise ValueError("catalog archive exceeds the extraction size limit")

        members: list[tuple[zipfile.ZipInfo, pathlib.PurePosixPath]] = []
        seen: set[pathlib.PurePosixPath] = set()
        for entry in entries:
            member = safe_member(entry.filename)
            mode = entry.external_attr >> 16
            if entry.is_dir() or not stat.S_ISREG(mode):
                raise ValueError(f"unsupported catalog archive entry: {entry.filename}")
            if member in seen:
                raise ValueError(f"duplicate catalog archive entry: {entry.filename}")
            seen.add(member)
            members.append((entry, member))

        required = {
            pathlib.PurePosixPath("catalog.json"),
            pathlib.PurePosixPath("runtime-root.json"),
            pathlib.PurePosixPath("timestamp.json"),
        }
        if not required.issubset(seen):
            missing = ", ".join(sorted(str(path) for path in required - seen))
            raise ValueError(f"catalog archive omits required files: {missing}")

        output.mkdir(parents=True, mode=0o755)
        try:
            for entry, member in members:
                destination = output.joinpath(*member.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                destination.chmod(0o644)
        except BaseException:
            shutil.rmtree(output)
            raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        extract(args.archive, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
