#!/usr/bin/env python3
"""Verify release checksums and reject unsafe archive members."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import stat
import tarfile
import zipfile

LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")
ALLOWED_MEMBERS = {"siorb", "siorb.exe", "README.md", "LICENSE"}
EXPECTED_MODES = {"siorb": 0o755, "siorb.exe": 0o755, "README.md": 0o644, "LICENSE": 0o644}
BINARY_ARCHIVE = re.compile(
    r"^siorb-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?-"
    r"(?:x86_64|aarch64)-(?:pc-windows-msvc|apple-darwin|unknown-linux-(?:gnu|musl))"
    r"\.(?:zip|tar\.gz)$"
)


def sha256(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def safe_relative(name: str, *, single_component: bool = False) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or (single_component and len(path.parts) != 1)
        or "\\" in name
        or any(character.isspace() and character not in {" "} for character in name)
    ):
        raise ValueError(f"unsafe archive/checksum path: {name}")
    return path


def inspect_archive(path: pathlib.Path) -> None:
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            names = []
            for entry in archive.infolist():
                name = safe_relative(entry.filename, single_component=True).as_posix()
                mode = entry.external_attr >> 16
                expected_mode = EXPECTED_MODES.get(name)
                if expected_mode is None:
                    raise ValueError(f"unexpected ZIP member: {entry.filename}")
                if entry.is_dir() or stat.S_ISLNK(mode) or (mode and not stat.S_ISREG(mode)):
                    raise ValueError(f"unsupported ZIP entry: {entry.filename}")
                if stat.S_IMODE(mode) != expected_mode:
                    raise ValueError(f"unexpected ZIP mode for {entry.filename}: {stat.S_IMODE(mode):04o}")
                names.append(name)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, mode="r:gz") as archive:
            names = []
            for entry in archive.getmembers():
                name = safe_relative(entry.name, single_component=True).as_posix()
                expected_mode = EXPECTED_MODES.get(name)
                if expected_mode is None:
                    raise ValueError(f"unexpected tar member: {entry.name}")
                if not entry.isfile():
                    raise ValueError(f"unsupported tar entry: {entry.name}")
                if stat.S_IMODE(entry.mode) != expected_mode:
                    raise ValueError(f"unexpected tar mode for {entry.name}: {stat.S_IMODE(entry.mode):04o}")
                names.append(name)
    else:
        return
    if len(names) != len(set(names)) or set(names) != ALLOWED_MEMBERS - ({"siorb.exe"} if "windows" not in path.name else {"siorb"}):
        raise ValueError(f"archive has unexpected or duplicate members: {path.name}: {sorted(names)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--checksums", type=pathlib.Path, required=True)
    parser.add_argument("--inspect-archives", action="store_true")
    args = parser.parse_args()
    if args.directory.is_symlink() or args.checksums.is_symlink():
        parser.error("directory and checksum manifest cannot be symlinks")
    directory = args.directory.resolve()
    lines = args.checksums.read_text(encoding="ascii").splitlines()
    seen = set()
    for number, line in enumerate(lines, 1):
        match = LINE.fullmatch(line)
        if not match:
            parser.error(f"malformed checksum line {number}")
        expected, raw_name = match.groups()
        name = safe_relative(raw_name)
        if name in seen:
            parser.error(f"duplicate checksum entry: {name}")
        seen.add(name)
        path = directory.joinpath(*name.parts)
        cursor = directory
        if any((cursor := cursor / part).is_symlink() for part in name.parts):
            parser.error(f"release path contains a symlink: {name}")
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            parser.error(f"missing release file: {name}")
        if not resolved.is_relative_to(directory) or not path.is_file():
            parser.error(f"missing or unsafe release file: {name}")
        actual = sha256(resolved)
        if actual != expected:
            parser.error(f"checksum mismatch for {name}: expected {expected}, got {actual}")
        is_binary_archive = BINARY_ARCHIVE.fullmatch(path.name) is not None
        if args.inspect_archives and is_binary_archive:
            try:
                inspect_archive(resolved)
            except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
                parser.error(str(error))
    if not seen:
        parser.error("checksum file is empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
