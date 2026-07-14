# `siorb-update` runtime fixtures

This directory contains byte-exact repositories for `siorb_update::verify_from_transport` with `consistent_snapshot = true`.

The positive `valid/` repository contains:

- `runtime-root.json`, a two-of-two Ed25519 root in `Signed<RootMetadata>` shape;
- `timestamp.json` describing the exact bytes of `1.snapshot.json`;
- `1.snapshot.json` describing the exact bytes of `1.targets.json`;
- `1.targets.json` describing the exact bytes of `catalog.json`;
- `catalog.json`, identical to `catalog/generated/catalog.json`;
- `fixture.json`, deterministic verification time, rollback state, and expected outcome.

`attacks/` contains complete runtime repositories for expired metadata, missing signature threshold, rollback, snapshot mix-and-match, metadata hash mismatch, truncated metadata, target hash mismatch, targets mix-and-match, and an invalid root threshold. Each carries its expected stable reason code.

The generator derives Ed25519 keys from conspicuously public fixture labels. These keys provide reproducible cryptographic tests only; they are compromised by design and must never sign production metadata.

```text
node catalog/fixtures/runtime-tuf/generate.mjs
node catalog/fixtures/runtime-tuf/generate.mjs --check
node catalog/verify-runtime-fixtures.mjs
```
