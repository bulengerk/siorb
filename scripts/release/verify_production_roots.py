#!/usr/bin/env python3
"""Fail closed unless release catalog roots are explicit production roots."""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import pathlib
import re


DIGEST = re.compile(r"^[0-9a-f]{64}$")
NON_PRODUCTION = re.compile(r"(?:^|[-_.])(dev|development|test|fixture)(?:$|[-_.])", re.IGNORECASE)
ROLES = ("root", "targets", "snapshot", "timestamp")
# SHA-256 of raw public keys shipped in catalog/trusted-root development fixtures.
# Block the material even if a fixture key is renamed before publication.
COMPROMISED_PUBLIC_KEYS = {
    "1559895aefd94a38fdd8a8fd3345ff2d3c9867c841580d5c0e1b59d765ba29ce",
    "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
    "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f",
    "5f9b247e2a654719f198e4f241d6b0df9a1a937a13ef5ef899f64d9285fce224",
    "6b75548d4adad52d0f2d88c485add378df6d4a55292d46a61d94f825a79fa437",
    "78b9ba5f3e29ab2a603808cc358cd3e80cb644010384956eac70f9968ce1c94f",
    "835f39466a9137b8a5f4348fdaad7c0179dd923a8d1b690e61dbd1bfb33850fc",
    "87e188d926be64d57de8661ede230ae302123fcb57bdc9f47366e4ac42809397",
    "91384c411e5af29648f17f922b402655b11ecaec1b33fc45796241963f95f202",
    "dac073e0123bdea59dd9b3bda9cf6037f63aca82627d7abcd5c4ac29dd74003e",
}


def role_key_ids(role: object, path: pathlib.Path, name: str) -> list[str]:
    if not isinstance(role, dict):
        raise ValueError(f"{path}: role {name!r} is not an object")
    raw = role.get("key_ids", role.get("keyids"))
    if not isinstance(raw, list) or not raw or not all(isinstance(value, str) and value for value in raw):
        raise ValueError(f"{path}: role {name!r} has no valid key IDs")
    threshold = role.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1 or threshold > len(raw):
        raise ValueError(f"{path}: role {name!r} has an invalid threshold")
    if name == "root" and threshold < 2:
        raise ValueError(f"{path}: production root role must require at least two signatures")
    return raw


def expiry(signed: dict[str, object], path: pathlib.Path) -> dt.datetime:
    if "expires_unix" in signed:
        value = signed["expires_unix"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{path}: expires_unix is invalid")
        return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
    value = signed.get("expires")
    if not isinstance(value, str):
        raise ValueError(f"{path}: root expiry is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{path}: root expiry is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{path}: root expiry must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def public_key_bytes(value: object, path: pathlib.Path, identifier: str) -> bytes:
    if not isinstance(value, dict) or value.get("scheme") != "ed25519":
        raise ValueError(f"{path}: key {identifier!r} is not Ed25519")
    keyval = value.get("keyval")
    encoded = keyval.get("public") if isinstance(keyval, dict) else value.get("public")
    if not isinstance(encoded, str):
        raise ValueError(f"{path}: key {identifier!r} has no public value")
    try:
        raw = bytes.fromhex(encoded) if isinstance(keyval, dict) else base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"{path}: key {identifier!r} has invalid public encoding") from error
    if len(raw) != 32:
        raise ValueError(f"{path}: key {identifier!r} is not a 32-byte Ed25519 public key")
    return raw


def verify_root(
    path: pathlib.Path, expected_digest: str, *, require_marker: bool
) -> dict[str, set[bytes]]:
    if not DIGEST.fullmatch(expected_digest):
        raise ValueError(f"{path}: expected SHA-256 must be a configured lowercase 64-digit digest")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: root must be a regular non-symlink file")
    payload = path.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected_digest:
        raise ValueError(f"{path}: root SHA-256 {actual} does not match the protected expected digest")
    try:
        envelope = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path}: root is not valid JSON") from error
    signed = envelope.get("signed") if isinstance(envelope, dict) else None
    if not isinstance(signed, dict) or signed.get("type", signed.get("_type")) != "root":
        raise ValueError(f"{path}: metadata is not a root envelope")
    if signed.get("consistent_snapshot") is not True:
        raise ValueError(f"{path}: production root must enable consistent snapshots")
    if expiry(signed, path) <= dt.datetime.now(dt.timezone.utc):
        raise ValueError(f"{path}: production root is expired")
    keys = signed.get("keys")
    roles = signed.get("roles")
    if not isinstance(keys, dict) or not isinstance(roles, dict):
        raise ValueError(f"{path}: keys or roles are missing")
    material = {identifier: public_key_bytes(value, path, identifier) for identifier, value in keys.items()}
    for identifier, public in material.items():
        if hashlib.sha256(public).hexdigest() in COMPROMISED_PUBLIC_KEYS:
            raise ValueError(f"{path}: key {identifier!r} uses compromised fixture public material")
    if len(set(material.values())) != len(material):
        raise ValueError(f"{path}: distinct key IDs reuse the same public key material")
    role_sets: dict[str, set[str]] = {}
    role_material: dict[str, set[bytes]] = {}
    for name in ROLES:
        identifiers = role_key_ids(roles.get(name), path, name)
        missing = set(identifiers).difference(keys)
        if missing:
            raise ValueError(f"{path}: role {name!r} refers to missing keys: {sorted(missing)}")
        if any(NON_PRODUCTION.search(identifier) for identifier in identifiers):
            raise ValueError(f"{path}: role {name!r} contains a development/test key ID")
        role_sets[name] = set(identifiers)
        role_material[name] = {material[identifier] for identifier in identifiers}
    for index, left in enumerate(ROLES):
        for right in ROLES[index + 1 :]:
            if role_sets[left].intersection(role_sets[right]):
                raise ValueError(f"{path}: roles {left!r} and {right!r} reuse key material")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) < int(roles["root"]["threshold"]):
        raise ValueError(f"{path}: root envelope does not carry its declared signature threshold")
    if require_marker:
        custom = signed.get("custom")
        if not isinstance(custom, dict) or custom.get("environment") != "production":
            raise ValueError(f"{path}: standard root must declare custom.environment as production")
    return role_material


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=pathlib.Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--tuf-root", type=pathlib.Path, required=True)
    parser.add_argument("--tuf-sha256", required=True)
    args = parser.parse_args()
    try:
        runtime_roles = verify_root(args.runtime_root, args.runtime_sha256, require_marker=False)
        standard_roles = verify_root(args.tuf_root, args.tuf_sha256, require_marker=True)
        if runtime_roles != standard_roles:
            raise ValueError("runtime and standard roots do not authorize the same role key material")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print("production catalog roots match protected fingerprints and role-separation policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
