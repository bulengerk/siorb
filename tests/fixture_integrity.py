#!/usr/bin/env python3
"""Check quality-corpus coverage and internal references without running Siorb."""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_BACKENDS = {
    "winget",
    "scoop",
    "chocolatey",
    "homebrew-formula",
    "homebrew-cask",
    "macports",
    "apt",
    "dnf",
    "pacman",
    "flatpak",
    "snap",
    "zypper",
    "apk",
}


def load(path: Path) -> object:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    failures: list[str] = []

    for path in sorted((ROOT / "tests").rglob("*.json")):
        try:
            load(path)
        except (OSError, json.JSONDecodeError) as error:
            failures.append(f"invalid JSON {path.relative_to(ROOT)}: {error}")

    backend_cases = load(ROOT / "tests/fixtures/backends/contract-cases.json")
    assert isinstance(backend_cases, list)
    covered_backends = {str(case["catalog_backend"]) for case in backend_cases}
    missing_backends = REQUIRED_BACKENDS - covered_backends
    if missing_backends:
        failures.append(f"backend contract coverage missing {sorted(missing_backends)}")

    platforms = []
    for path in sorted((ROOT / "tests/golden/platform").glob("*.json")):
        value = load(path)
        assert isinstance(value, dict)
        platforms.append(value)
    required_platforms = {
        ("windows", None, "x86_64"),
        ("windows", None, "arm64"),
        ("macos", None, "x86_64"),
        ("macos", None, "arm64"),
        ("linux", "debian", "x86_64"),
        ("linux", "ubuntu", "arm64"),
        ("linux", "fedora", "x86_64"),
        ("linux", "rhel", "arm64"),
        ("linux", "arch", "x86_64"),
        ("linux", "archarm", "arm64"),
        ("linux", "opensuse-leap", "x86_64"),
        ("linux", "opensuse-leap", "arm64"),
        ("linux", "alpine", "x86_64"),
        ("linux", "alpine", "arm64"),
    }
    observed_platforms = {
        (value["os"], value["distribution"], value["architecture"])
        for value in platforms
    }
    missing_platforms = required_platforms - observed_platforms
    if missing_platforms:
        failures.append(f"platform golden coverage missing {sorted(missing_platforms)}")

    scenarios = load(ROOT / "tests/end-to-end/scenarios.json")
    assert isinstance(scenarios, list)
    for scenario in scenarios:
        assert isinstance(scenario, dict)
        name = scenario.get("name", "unnamed")
        if scenario.get("requires_mutation") is not False:
            failures.append(f"default E2E scenario is not host-safe: {name}")
        for field in ("platform_golden", "catalog_fixture", "state_fixture"):
            if field in scenario and not (ROOT / str(scenario[field])).is_file():
                failures.append(f"E2E scenario {name} has missing {field}")

    for path in sorted((ROOT / "tests/security").glob("*.json")):
        corpus = load(path)
        if not isinstance(corpus, list) or not corpus:
            failures.append(f"security corpus is empty: {path.name}")
            continue
        for index, case in enumerate(corpus):
            if isinstance(case, dict) and case.get("valid") is False and "reason_code" not in case:
                failures.append(f"{path.name}[{index}] rejects without a reason_code")

    with (ROOT / "fuzz/Cargo.toml").open("rb") as stream:
        fuzz_manifest = tomllib.load(stream)
    fuzz_bins = fuzz_manifest.get("bin", [])
    for target in fuzz_bins:
        path = ROOT / "fuzz" / str(target["path"])
        if not path.is_file():
            failures.append(f"fuzz target is missing: {path.relative_to(ROOT)}")

    schema_ids: set[str] = set()
    for path in sorted((ROOT / "schemas/v1").glob("*.schema.json")):
        schema = load(path)
        assert isinstance(schema, dict)
        schema_id = str(schema.get("$id", ""))
        if not schema_id or schema_id in schema_ids:
            failures.append(f"schema has missing or duplicate $id: {path.name}")
        schema_ids.add(schema_id)

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        f"fixture integrity passed: {len(platforms)} platforms, "
        f"{len(backend_cases)} backend cases, {len(scenarios)} E2E scenarios, "
        f"{len(fuzz_bins)} fuzz targets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
