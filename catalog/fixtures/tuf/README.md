# Static update fixtures

The `valid/` tree is an immutable, fully signed TUF-compatible metadata snapshot bound by length and SHA-256 from timestamp → snapshot → targets → `catalog.json`. Its private fixture keys are intentionally absent, so it is not regenerated when the current runtime catalog changes. Current-catalog byte binding is covered by `fixtures/runtime-tuf/`, whose deterministic public development keys are explicitly non-production. `trusted-root/root.json` uses a two-of-two root threshold and single-key online roles. Its `custom.environment` is deliberately `development-fixture`; it must never be reused as a production signing root.

Negative fixtures each isolate one expected rejection:

- `expired`: expired timestamp metadata;
- `rollback`: a snapshot version lower than the trusted version;
- `freeze`: a once-valid timestamp that is no longer fresh;
- `invalid-threshold`: one signature for a two-signature root role;
- `changed-root`: a replacement root not signed by the currently trusted root keys;
- `hash-mismatch`: target bytes that do not match signed targets metadata;
- `mirror-inconsistency`: a snapshot carrying a different targets hash;
- `truncated`: incomplete JSON metadata;
- `interrupted-update`: an incomplete staged update that must leave the current catalog active.

Run `node catalog/verify-fixtures.mjs` to verify signatures, thresholds, expiry at the fixture epoch, metadata hashes, target hashes, and the intended adversarial conditions. The signing keys used to create the fixture are not part of the repository.
