# Siorb catalog

`packages/*.toml` is the only package-data source of truth. Each file describes one stable logical package and exact, reviewed backend mappings. Generated JSON and the static website must never be edited directly.

## Validate and generate

```text
node catalog/validate.mjs
node catalog/build-index.mjs
node catalog/build-index.mjs --check
node catalog/verify-fixtures.mjs
node catalog/fixtures/runtime-tuf/generate.mjs --check
node catalog/verify-runtime-fixtures.mjs
node website/build.mjs
node website/build.mjs --check
```

Validation rejects unsafe identifiers, aliases that collide with another package or a CLI command, option-like backend IDs, unknown enum values, missing evidence, and incomplete curated top-package coverage. A mapping is reviewable only when its exact backend ID, HTTPS evidence, provenance, architectures, trust level, and review date are present.

`index.json` is the inspectable generated index. `generated/catalog.json` is the compact runtime fixture embedded by `siorb-catalog`. Both carry an `_generated` notice with their regeneration command, are deterministic, and have a fixed generation timestamp taken from `catalog.toml`.

## Contribution review

1. Add or update exactly one package manifest.
2. Confirm every source ID in the linked native repository or authenticated sandbox registry.
3. Record the evidence URL and current UTC review date on the package and each source.
4. Prefer native sources, then sandboxed application sources. Do not add unverified downloads or installer commands.
5. Run all four commands above and include the generated diff.

Security-sensitive corrections should follow the private reporting guidance linked from the generated website. Public package changes remain useful to forks because no owner-operated service is involved.
