# Repository instructions

- Build with `cargo build --workspace --all-features`; the CLI binary is `siorb`.
- Validate with `cargo fmt --check`, strict workspace Clippy, workspace tests, then `cargo xtask verify`.
- Run `cargo xtask generate-catalog` and `cargo xtask build-site` after catalog changes; never hand-edit files marked generated.
- Never turn catalog text into shell syntax. Backends accept validated executable paths and separate argument vectors. Resolve and plan before privilege or mutation; do not weaken signature, digest, rollback, expiry, archive, or policy checks.
- Keep JSON `schema_version` and exit-code compatibility. Update schemas, tests, docs, and examples with behavior changes.
- Host-mutating tests require explicit opt-in. Never store credentials, identity, telemetry, or unredacted backend secrets.
- Before every Codex response after meaningful project work, append exactly one immutable UTC entry to the physically final `## Codex Work Sessions` section in `README.md`. Never edit earlier entries; use the exact fields documented there and run `cargo xtask verify`.
