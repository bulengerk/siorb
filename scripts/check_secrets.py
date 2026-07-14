#!/usr/bin/env python3
"""Conservative secret-pattern gate for tracked text files."""

from __future__ import annotations

import pathlib
import re
import subprocess


def patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        ("private key", re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
        ("GitHub fine-grained token", re.compile("github_pat_" + r"[A-Za-z0-9_]{30,}")),
        ("AWS access key", re.compile("AKIA" + r"[A-Z0-9]{16}")),
        ("Slack token", re.compile("xox" + r"[aboprs]-[A-Za-z0-9-]{20,}")),
    ]


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    failures: list[str] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = pathlib.Path(raw.decode("utf-8", errors="strict"))
        path = root / relative
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            continue
        if b"\0" in data or len(data) > 5 * 1024 * 1024:
            continue
        text = data.decode("utf-8", errors="replace")
        for label, pattern in patterns():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                failures.append(f"{relative.as_posix()}:{line}: possible {label}")
    if failures:
        print("\n".join(failures))
        print("If this is a fixture, replace it with an unmistakably invalid redacted value.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
