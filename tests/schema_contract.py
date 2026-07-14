#!/usr/bin/env python3
"""Validate every published schema and its positive/negative fixture corpus."""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

try:
    import jsonschema
except ImportError:
    print(
        "error: tests/schema_contract.py requires the 'jsonschema' Python package",
        file=sys.stderr,
    )
    raise SystemExit(2)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas" / "v1"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "schemas" / "v1"
PLATFORM_GOLDEN_ROOT = ROOT / "tests" / "golden" / "platform"

FORMAT_CHECKER = jsonschema.FormatChecker()


@FORMAT_CHECKER.checks("date-time")
def is_rfc3339_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return True
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return "T" in value and (value.endswith("Z") or "+" in value[10:] or "-" in value[10:])


@FORMAT_CHECKER.checks("uuid")
def is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return True
    try:
        return str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


@FORMAT_CHECKER.checks("uri")
def is_uri(value: object) -> bool:
    if not isinstance(value, str):
        return True
    parsed = urlsplit(value)
    return bool(parsed.scheme and (parsed.netloc or parsed.scheme == "file"))


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    schema_paths = sorted(SCHEMA_ROOT.glob("*.schema.json"))
    if not schema_paths:
        print("error: no schemas found", file=sys.stderr)
        return 1

    schemas = {path.name: load_json(path) for path in schema_paths}
    store: dict[str, object] = {}
    for path in schema_paths:
        schema = schemas[path.name]
        assert isinstance(schema, dict)
        jsonschema.Draft202012Validator.check_schema(schema)
        store[path.as_uri()] = schema
        if "$id" in schema:
            store[str(schema["$id"])] = schema

    cases = load_json(FIXTURE_ROOT / "cases.json")
    assert isinstance(cases, list)
    failures: list[str] = []

    for case in cases:
        assert isinstance(case, dict)
        name = str(case["name"])
        schema_name = str(case["schema"])
        instance_path = FIXTURE_ROOT / str(case["instance"])
        expected_valid = bool(case["valid"])
        schema = schemas[schema_name]
        resolver = jsonschema.RefResolver.from_schema(schema, store=store)
        validator = jsonschema.Draft202012Validator(
            schema,
            resolver=resolver,
            format_checker=FORMAT_CHECKER,
        )
        errors = sorted(
            validator.iter_errors(load_json(instance_path)),
            key=lambda error: list(error.absolute_path),
        )
        actual_valid = not errors
        if actual_valid != expected_valid:
            detail = "valid" if actual_valid else errors[0].message
            failures.append(f"{name}: expected valid={expected_valid}, got {detail}")
            continue

        expected_fragment = case.get("error_contains")
        if expected_fragment and errors:
            messages = "\n".join(error.message for error in errors)
            if str(expected_fragment) not in messages:
                failures.append(
                    f"{name}: no validation error contained {expected_fragment!r}; "
                    f"got {messages!r}"
                )

    platform_schema = schemas["platform-context.schema.json"]
    platform_validator = jsonschema.Draft202012Validator(
        platform_schema,
        resolver=jsonschema.RefResolver.from_schema(platform_schema, store=store),
        format_checker=FORMAT_CHECKER,
    )
    platform_paths = sorted(PLATFORM_GOLDEN_ROOT.glob("*.json"))
    for platform_path in platform_paths:
        errors = list(platform_validator.iter_errors(load_json(platform_path)))
        if errors:
            failures.append(f"{platform_path.name}: {errors[0].message}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print(
        f"validated {len(schema_paths)} schemas, {len(cases)} fixture cases, "
        f"and {len(platform_paths)} platform goldens"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
