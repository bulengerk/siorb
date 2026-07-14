#!/usr/bin/env python3
"""Security regression tests for release archive/checksum verification."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/release/verify_release.py"
VERIFY_ROOTS = ROOT / "scripts/release/verify_production_roots.py"
EXTRACT_CATALOG = ROOT / "scripts/release/extract_catalog_snapshot.py"
GENERATE_METADATA = ROOT / "scripts/release/generate_release_metadata.py"


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseVerifierTests(unittest.TestCase):
    def run_verifier(self, directory: pathlib.Path, *, inspect: bool = False) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(VERIFY),
            "--directory",
            str(directory),
            "--checksums",
            str(directory / "SHA256SUMS"),
        ]
        if inspect:
            command.append("--inspect-archives")
        return subprocess.run(command, check=False, capture_output=True, text=True)

    def test_checksum_entry_cannot_cross_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-release-verifier-") as temporary:
            root = pathlib.Path(temporary)
            release = root / "release"
            outside = root / "outside"
            release.mkdir()
            outside.mkdir()
            payload = outside / "payload"
            payload.write_bytes(b"outside release directory")
            (release / "escape").symlink_to(outside, target_is_directory=True)
            (release / "SHA256SUMS").write_text(
                f"{digest(payload)}  escape/payload\n", encoding="ascii"
            )

            result = self.run_verifier(release)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlink", result.stderr)

    def test_binary_archive_requires_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-release-verifier-") as temporary:
            release = pathlib.Path(temporary)
            archive_path = release / "siorb-0.1.0-x86_64-pc-windows-msvc.zip"
            members = {
                "siorb.exe": (b"binary", 0o644),
                "README.md": (b"readme", 0o644),
                "LICENSE": (b"license", 0o644),
            }
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, (content, mode) in members.items():
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | mode) << 16
                    archive.writestr(info, content)
            (release / "SHA256SUMS").write_text(
                f"{digest(archive_path)}  {archive_path.name}\n", encoding="ascii"
            )

            result = self.run_verifier(release, inspect=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected ZIP mode", result.stderr)

    def test_catalog_snapshot_extracts_complete_static_layout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-catalog-extract-") as temporary:
            root = pathlib.Path(temporary)
            archive_path = root / "catalog.zip"
            members = {
                "catalog.json": b"{}\n",
                "runtime-root.json": b"{}\n",
                "timestamp.json": b"{}\n",
                "1.snapshot.json": b"{}\n",
                "1.targets.json": b"{}\n",
                "artifacts/siorb.zip": b"payload",
            }
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, content in members.items():
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, content)
            output = root / "mirror"

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXTRACT_CATALOG),
                    "--archive",
                    str(archive_path),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((output / "artifacts/siorb.zip").read_bytes(), b"payload")

    def test_catalog_snapshot_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-catalog-extract-") as temporary:
            root = pathlib.Path(temporary)
            archive_path = root / "catalog.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name in ("catalog.json", "runtime-root.json", "timestamp.json", "../escape"):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, b"{}\n")
            output = root / "mirror"

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXTRACT_CATALOG),
                    "--archive",
                    str(archive_path),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe catalog archive member", result.stderr)
            self.assertFalse(output.exists())

    def test_production_root_gate_accepts_separated_fingerprinted_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-production-roots-") as temporary:
            root = pathlib.Path(temporary)
            key_ids = ["root-a", "root-b", "targets-a", "snapshot-a", "timestamp-a"]
            raw_keys = {identifier: bytes([index]) * 32 for index, identifier in enumerate(key_ids, 1)}
            runtime_keys = {
                identifier: {
                    "scheme": "ed25519",
                    "public": base64.b64encode(value).decode("ascii"),
                }
                for identifier, value in raw_keys.items()
            }
            standard_keys = {
                identifier: {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": value.hex()},
                }
                for identifier, value in raw_keys.items()
            }
            runtime_roles = {
                "root": {"key_ids": ["root-a", "root-b"], "threshold": 2},
                "targets": {"key_ids": ["targets-a"], "threshold": 1},
                "snapshot": {"key_ids": ["snapshot-a"], "threshold": 1},
                "timestamp": {"key_ids": ["timestamp-a"], "threshold": 1},
            }
            signatures = [{"key_id": "root-a"}, {"key_id": "root-b"}]
            runtime = {
                "signed": {
                    "type": "root",
                    "spec_version": "1.0",
                    "version": 1,
                    "expires_unix": 4_102_444_800,
                    "consistent_snapshot": True,
                    "keys": runtime_keys,
                    "roles": runtime_roles,
                },
                "signatures": signatures,
            }
            standard_roles = {
                name: {"keyids": value["key_ids"], "threshold": value["threshold"]}
                for name, value in runtime_roles.items()
            }
            standard = {
                "signed": {
                    "_type": "root",
                    "spec_version": "1.0.31",
                    "version": 1,
                    "expires": "2100-01-01T00:00:00Z",
                    "consistent_snapshot": True,
                    "keys": standard_keys,
                    "roles": standard_roles,
                    "custom": {"environment": "production"},
                },
                "signatures": [{"keyid": "root-a"}, {"keyid": "root-b"}],
            }
            runtime_path = root / "runtime-root.json"
            standard_path = root / "root.json"
            runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
            standard_path.write_text(json.dumps(standard), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(VERIFY_ROOTS),
                    "--runtime-root",
                    str(runtime_path),
                    "--runtime-sha256",
                    digest(runtime_path),
                    "--tuf-root",
                    str(standard_path),
                    "--tuf-sha256",
                    digest(standard_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_checked_in_development_root_is_rejected(self) -> None:
        runtime_path = ROOT / "catalog/trusted-root/runtime-root.json"
        standard_path = ROOT / "catalog/trusted-root/root.json"
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFY_ROOTS),
                "--runtime-root",
                str(runtime_path),
                "--runtime-sha256",
                digest(runtime_path),
                "--tuf-root",
                str(standard_path),
                "--tuf-sha256",
                digest(standard_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compromised fixture public material", result.stderr)

    def test_release_metadata_matches_xtask_manifest_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-release-metadata-") as temporary:
            release = pathlib.Path(temporary)
            subjects = [
                release / "siorb-1.2.3-x86_64-unknown-linux-gnu.tar.gz",
                release / "siorb-1.2.3.spdx.json",
            ]
            subjects[0].write_bytes(b"archive payload")
            subjects[1].write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATE_METADATA),
                    "--directory",
                    str(release),
                    "--version",
                    "1.2.3",
                    "--repository",
                    "fork-owner/siorb",
                    "--server-url",
                    "https://github.com",
                    "--workflow-ref",
                    "fork-owner/siorb/.github/workflows/release.yml@refs/tags/v1.2.3",
                    "--commit",
                    "a" * 40,
                    "--run-id",
                    "1234",
                    "--run-attempt",
                    "2",
                    "--source-date-epoch",
                    "1234567890",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((release / "ARTIFACTS.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "1.0")
            self.assertEqual(manifest["version"], "1.2.3")
            self.assertEqual(manifest["target"], "multi-platform")
            self.assertEqual(manifest["signing_status"], "github-release")
            records = manifest["artifacts"]
            self.assertEqual(
                [record["path"] for record in records],
                sorted(record["path"] for record in records),
            )
            self.assertEqual(len(records), 4)
            for record in records:
                artifact = release / record["path"]
                self.assertTrue(artifact.is_file())
                self.assertEqual(record["length"], artifact.stat().st_size)
                self.assertEqual(record["sha256"], digest(artifact))

            for subject in subjects:
                provenance_path = subject.with_name(f"{subject.name}.provenance.json")
                provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    provenance["subject"],
                    [{"digest": {"sha256": digest(subject)}, "name": subject.name}],
                )
                self.assertEqual(
                    provenance["predicate"]["runDetails"]["builder"]["id"],
                    "https://github.com/fork-owner/siorb/.github/workflows/release.yml@refs/tags/v1.2.3",
                )

    def test_release_metadata_rejects_a_mismatched_workflow_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="siorb-release-metadata-") as temporary:
            release = pathlib.Path(temporary)
            (release / "artifact.bin").write_bytes(b"artifact")
            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATE_METADATA),
                    "--directory",
                    str(release),
                    "--version",
                    "1.2.3",
                    "--repository",
                    "fork-owner/siorb",
                    "--server-url",
                    "https://github.com",
                    "--workflow-ref",
                    "upstream/siorb/.github/workflows/release.yml@refs/tags/v1.2.3",
                    "--commit",
                    "a" * 40,
                    "--run-id",
                    "1234",
                    "--run-attempt",
                    "1",
                    "--source-date-epoch",
                    "1234567890",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workflow ref must be fork-owner/siorb", result.stderr)


if __name__ == "__main__":
    unittest.main()
