# Stable JSON contracts

Siorb's machine-readable contracts are versioned independently from the
executable. `schemas/v1/` contains the public `schema_version: "1.0"` contract
and uses JSON Schema Draft 2020-12.

Rules:

- published schemas are immutable; compatible additions go into a new minor
  schema and incompatible changes require a new major directory;
- an output envelope always validates against `command-output.schema.json`;
- domain payloads embedded in `results` additionally validate against their
  domain schema;
- unknown top-level envelope fields are rejected, while explicitly documented
  extension maps remain open;
- digests use lowercase 64-character hexadecimal SHA-256 form;
- timestamps are UTC RFC 3339 except Unix-time fields, which are integer Unix
  seconds;
- examples under `tests/fixtures/schemas/` are executable conformance cases.

Run the standalone fixture validator with:

```text
python3 tests/schema_contract.py
```

It requires the Python `jsonschema` package. The canonical repository gate is
`cargo xtask test-schemas`, which must enforce the same cases without Python.
