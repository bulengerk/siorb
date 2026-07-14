# Siorb test assets

The default test suite is host-safe and never runs a native package manager.
Its successful fake-backend scenario changes only temporary installed-state
and Siorb receipt fixtures. Real host mutation is reserved for the manually
dispatched disposable-runner workflow; scenario rows that can mutate a host
must be marked `requires_mutation: true` and skipped by default.

Layout:

- `fixtures/schemas/` contains positive and adversarial schema examples;
- `fixtures/platform-detection/` contains injectable raw system facts;
- `fixtures/backends/` contains captured, bounded adapter responses;
- `golden/platform/` contains the current golden corpus and covers supported
  host families, architecture/translation combinations, and adverse host
  states;
- `security/` contains attack corpora consumed as inert data by host-safe
  rejection tests;
- `end-to-end/` contains declarative, fake-backend CLI scenarios and their
  contract runner;
- `integration/` contains tests spanning crate boundaries and local state.

The schema corpus can be checked independently with
`python3 tests/schema_contract.py`. Corpus coverage and cross-file references
are checked with `python3 tests/fixture_integrity.py`. Production gates should also run
`cargo xtask test-schemas`, `cargo test --workspace --all-features`, and the
cross-crate package:

```text
cargo test --manifest-path tests/Cargo.toml --all-targets
```

Golden updates are reviewed changes to a public contract. Never rewrite them
automatically as a side effect of an ordinary test run.
