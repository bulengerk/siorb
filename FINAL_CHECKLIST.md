# Release readiness checklist

Each checkbox names reproducible evidence. Keep unchecked until the command succeeds in a clean release environment.

- [x] Formatting: `cargo fmt --all -- --check`.
- [x] Lints: `cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings`.
- [x] Tests: `cargo test --workspace --all-features --locked --offline` plus the standalone test workspace and fuzz-target compilation.
- [x] Repository invariants and README log: `cargo xtask verify`.
- [x] Versioned schemas and examples: `cargo xtask test-schemas`.
- [x] Catalog schema, alias, source, evidence, count, and signature checks: `cargo xtask test-catalog`.
- [x] Documentation examples and links: `cargo xtask test-docs`.
- [x] Deterministic static website: `cargo xtask build-site` generated 120 package pages and passed site validation.
- [x] Dependency vulnerabilities: `cargo audit` passed for the workspace, standalone tests, and fuzz lockfiles.
- [x] License/source policy: `cargo deny check`.
- [ ] Cross-platform behavior: successful `ci.yml` matrix evidence for Windows, macOS, and Linux.
- [x] Host-safe backend contracts: `cargo test --manifest-path tests/Cargo.toml --test backend_contract`.
- [x] Catalog attacks: `cargo test --manifest-path tests/Cargo.toml --test update_security`.
- [x] Archive attacks: `cargo test --manifest-path tests/Cargo.toml --test archive_security`.
- [x] Local performance gate: `cargo xtask benchmark --check` against a 10x catalog.
- [ ] Reference-runner performance evidence: repeat `cargo xtask benchmark --check` on the documented runner.
- [x] Local signed release candidate: `cargo xtask release-local --out dist`.
- [x] Release contents: `sha256sum -c dist/SHA256SUMS` plus SBOM, provenance, signatures, and symbols listed by `cargo xtask package --verify dist`.
- [ ] Clean fork test: documented clone/build/test/site/release-local procedure succeeds without owner infrastructure.
- [ ] Production publication owner action: configure protected `release` and `pages` environments and required signing/notarization secrets documented in `docs/release-process.md`, then approve the tag workflow.
