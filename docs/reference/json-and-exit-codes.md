# JSON envelopes and exit codes

With `--json`, Siorb writes one versioned machine envelope to standard output
and diagnostics to standard error. `schemas/v1/command-output.schema.json` is
normative. The envelope includes schema version, command, status, normalized
platform, catalog and optional policy identities, results/warnings/errors, and a
locally generated correlation ID. It contains no credential or unnecessary user
identity.

Current stable exit families are:

| Code | Family |
|---:|---|
| 0 | success |
| 2 | invalid input |
| 10 | unresolved package |
| 11 | ambiguous package |
| 12 | policy rejection |
| 20 | catalog failure |
| 30 | backend absent |
| 31 | privilege denied |
| 32 | backend execution failure |
| 40 | verification failure |
| 50 | partial completion |
| 70 | internal error |

Automation must inspect both exit code and structured status. In particular,
partial completion means state may have changed; it is not equivalent to a
clean failure. Consumers should ignore unknown fields only where the active
schema permits them and must reject an unsupported major `schema_version`.
