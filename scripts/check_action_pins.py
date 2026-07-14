#!/usr/bin/env python3
"""Fail when a workflow references a remote action without an immutable SHA."""

from __future__ import annotations

import pathlib
import re

USE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@([0-9a-f]{40})$")
DOCKER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    failures: list[str] = []
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        for match in USE.finditer(text):
            value = match.group(1).strip("'\"")
            if value.startswith("./"):
                continue
            if not ACTION.fullmatch(value) and not DOCKER.fullmatch(value):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(root)}:{line}: remote action is not SHA-pinned: {value}")
    if failures:
        print("\n".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
