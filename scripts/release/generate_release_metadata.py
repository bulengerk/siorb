#!/usr/bin/env python3
"""Generate per-artifact provenance and the production artifact manifest."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import urllib.parse


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
SCHEMA_VERSION = "1.0"


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def regular_files(directory: pathlib.Path) -> list[pathlib.Path]:
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"release directory contains a symlink: {path}")
        if path.is_file():
            files.append(path)
    return files


def normalized_server_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "server URL must be an HTTPS origin without credentials, query, or fragment"
        )
    return value.rstrip("/")


def generated_at(epoch: str | None) -> str:
    if epoch is None or not epoch.isascii() or not epoch.isdigit():
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    timestamp = int(epoch)
    return (
        dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def write_json(path: pathlib.Path, value: object) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace a symlink output: {path}")
    encoded = f"{json.dumps(value, indent=2, sort_keys=True)}\n"
    path.write_text(encoded, encoding="utf-8", newline="\n")


def artifact_kind(relative: str) -> str:
    lowercase = relative.lower()
    if lowercase.endswith(".tar.gz") or lowercase.endswith(".zip"):
        return "native-archive"
    if relative.endswith(".spdx.json"):
        return "sbom"
    if relative.endswith(".provenance.json"):
        return "provenance"
    return "release-evidence"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True, help="GitHub OWNER/REPOSITORY")
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--source-date-epoch", default=os.environ.get("SOURCE_DATE_EPOCH"))
    args = parser.parse_args()

    if not VERSION.fullmatch(args.version):
        parser.error("version must be MAJOR.MINOR.PATCH with an optional SemVer prerelease")
    if not REPOSITORY.fullmatch(args.repository):
        parser.error("repository must be OWNER/REPOSITORY")
    expected_workflow_ref = (
        f"{args.repository}/.github/workflows/release.yml@refs/tags/v{args.version}"
    )
    if args.workflow_ref != expected_workflow_ref:
        parser.error(f"workflow ref must be {expected_workflow_ref}")
    if not COMMIT.fullmatch(args.commit):
        parser.error("commit must be a full 40-character Git commit ID")
    if (
        not args.run_id.isascii()
        or not args.run_id.isdigit()
        or int(args.run_id) < 1
    ):
        parser.error("run ID must be a positive integer")
    if (
        not args.run_attempt.isascii()
        or not args.run_attempt.isdigit()
        or int(args.run_attempt) < 1
    ):
        parser.error("run attempt must be a positive integer")
    try:
        server_url = normalized_server_url(args.server_url)
        timestamp = generated_at(args.source_date_epoch)
    except ValueError as error:
        parser.error(str(error))

    if args.directory.is_symlink():
        parser.error("directory cannot be a symlink")
    directory = args.directory.resolve()
    if not directory.is_dir():
        parser.error("directory does not exist")

    try:
        subjects = regular_files(directory)
    except ValueError as error:
        parser.error(str(error))
    if not subjects:
        parser.error("release directory has no artifact subjects")
    for path in subjects:
        if path.name in {"ARTIFACTS.json", "SHA256SUMS"} or path.name.endswith(
            (".provenance.json", ".sigstore.json")
        ):
            parser.error(f"release metadata already exists or was generated out of order: {path}")

    workflow_url = f"{server_url}/{args.workflow_ref}"
    source_url = f"{server_url}/{args.repository}"
    invocation_url = (
        f"{source_url}/actions/runs/{args.run_id}/attempts/{args.run_attempt}"
    )
    commit = args.commit.lower()
    for subject in subjects:
        relative = subject.relative_to(directory).as_posix()
        provenance_path = subject.with_name(f"{subject.name}.provenance.json")
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"digest": {"sha256": digest(subject)}, "name": relative}],
            "predicate": {
                "buildDefinition": {
                    "buildType": workflow_url,
                    "externalParameters": {
                        "artifact": relative,
                        "version": args.version,
                        "workflow_ref": args.workflow_ref,
                    },
                    "internalParameters": {"production_release": True},
                    "resolvedDependencies": [
                        {
                            "digest": {"gitCommit": commit},
                            "uri": f"git+{source_url}@{commit}",
                        }
                    ],
                },
                "runDetails": {
                    "builder": {"id": workflow_url},
                    "metadata": {
                        "finishedOn": timestamp,
                        "invocationId": invocation_url,
                        "startedOn": timestamp,
                    },
                },
            },
        }
        try:
            write_json(provenance_path, provenance)
        except ValueError as error:
            parser.error(str(error))

    records = []
    try:
        files = regular_files(directory)
    except ValueError as error:
        parser.error(str(error))
    for path in files:
        if path.name in {"ARTIFACTS.json", "SHA256SUMS"}:
            continue
        relative = path.relative_to(directory).as_posix()
        records.append(
            {
                "kind": artifact_kind(relative),
                "length": path.stat().st_size,
                "path": relative,
                "sha256": digest(path),
            }
        )
    records.sort(key=lambda record: record["path"])
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "version": args.version,
        "target": "multi-platform",
        "signing_status": "github-release",
        "artifacts": records,
    }
    try:
        write_json(directory / "ARTIFACTS.json", manifest)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
