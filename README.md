# Siorb

Siorb turns a portable software intent into an explainable, policy-aware plan for the native package tools already trusted by the host. The project is under active development; commands that can mutate a machine always plan first and require explicit consent.

Codex translated the project specification into the architecture, code, tests, catalog, documentation, packaging, and release automation; maintainers retain review and release-signing responsibility.

## Terminal demo

```console
$ siorb install firefox --dry-run
PLAN install firefox
  source: apt / firefox
  scope: system (elevation required for the execution step)
  action: /usr/bin/apt-get install --yes -- firefox
No changes made (--dry-run).
```

## Security and infrastructure

Resolution happens locally from a bundled catalog. Siorb has no accounts, telemetry, hosted resolver, database, daemon, or owner-operated runtime service. Optional catalog mirrors are static and verified before use. Backend commands are constructed as an executable plus argument vector, never as shell text.

## Supported hosts and package tools

Siorb detects, rather than assumes, available tools. Adapters cover WinGet, Scoop, Chocolatey, Homebrew formulae and casks, MacPorts, APT, DNF/DNF5, Pacman, Zypper, APK, Snap, and Flatpak. The catalog only selects sources compatible with the detected OS, distribution, architecture, scope, channel, policy, and adapter capabilities.

## Installation

Build from a pinned Rust toolchain:

```sh
git clone https://github.com/bulengerk/siorb.git
cd siorb
cargo build --release --locked -p siorb-cli
cargo xtask verify
./target/release/siorb version
```

Release archives, native packages, checksums, SBOMs, signatures, and verification instructions are produced by the release workflow. Do not trust an artifact whose digest or signature cannot be verified.

## Quick start

```sh
siorb search browser
siorb info firefox
siorb plan install firefox
siorb install firefox --dry-run --explain
siorb install firefox --yes
siorb doctor --json
```

`siorb firefox` is interactive shorthand for `siorb install firefox`; automation should use the canonical command.

## Commands and global options

The stable surface includes install, remove, upgrade, search, info, list, plan, why, doctor, adopt, reconcile, repair, migrate, bundle, pin, unpin, hold, unhold, backend, source, catalog, policy, audit, verify, self update, completion, and version.

Global options keep one meaning throughout the CLI: `--dry-run`, `--json`, `--non-interactive`, `--yes`, `--accept-agreements`, `--via`, `--source`, `--scope`, `--channel`, `--version`, `--arch`, `--offline`, `--explain`, `--catalog`, `--policy`, `--color`, `--verbose`, and `--quiet`. JSON is written to stdout and diagnostics to stderr. Non-interactive mode never prompts.

## Portable bundles and migration

```toml
schema_version = "1.0"

[[packages]]
id = "firefox"
state = "present"
channel = "stable"
scope = "auto"

[[packages]]
id = "vscode"
state = "present"
optional = true
```

Validate and preview with `siorb bundle validate siorb.toml` and `siorb bundle plan siorb.toml`; apply only after reviewing the resulting platform-specific plan. Deterministic locks can be reviewed with `siorb bundle refresh siorb.toml --lock siorb.lock.json` and enforced during apply with `--lock`. `siorb migrate export --output siorb.toml` exports portable intent rather than pretending native package identities transfer between operating systems.

## Architecture

The Rust workspace separates CLI presentation, domain types, platform detection, catalog parsing, policy, resolution, planning, typed backend adapters, bounded execution, state, bundles, signed updates, and repository automation. Essential decisions are local:

```text
bundled/signed static catalog + platform facts + local policy + receipts
                              |
                    resolver and planner
                              |
             native backend or verified artifact
```

## Catalog, signatures, offline mode, and mirrors

Catalog manifests under `catalog/packages/` are the reviewable source of truth. `cargo xtask generate-catalog` creates deterministic indexes and the static website. A bundled snapshot supports offline search, information, explanation, and planning. `siorb catalog verify PATH` verifies a complete local signed repository; catalog updates apply the same rules to static HTTPS mirrors. Rollback and expired metadata are never silently accepted.

## Privacy, privilege, receipts, and recovery

Siorb stores no user identity and sends no telemetry. It resolves without elevation and elevates only individual backend steps. An append-only journal records attempted changes; atomic receipts record installed, adopted, or observed state in the platform application-data directory. Interrupted transactions are surfaced by `reconcile`, and partial completion is never described as an atomic rollback.

## Contributing

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask verify
cargo xtask test-schemas
cargo xtask test-catalog
cargo xtask test-docs
cargo xtask build-site
```

See `CONTRIBUTING.md`, `AGENTS.md`, the authoring references in `docs/`, and `SECURITY.md`. Host-mutating tests are opt-in; the default suite is workstation-safe.

## Releases and support

Release construction and verification are documented in `docs/release-process.md`. Report vulnerabilities through the private process in `SECURITY.md`; use GitHub issues for reproducible non-sensitive defects and mapping health reports.

## Limitations and roadmap

Native tool behavior still varies by OS version and upstream repository. Siorb reports unsupported capabilities rather than emulating them unsafely. Production signing, notarization, package-store publication, and protected release environments require the repository owner's credentials; local development keys cover the non-secret verification path. Milestone status and evidence live in `PLANS.md` and `FINAL_CHECKLIST.md`.

## Codex Work Sessions

### 2026-07-14 05:56 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Implement the complete Siorb specification, document Codex usage, validate the result, and publish it.
- **Work completed:** Built the cross-platform Rust CLI, signed catalog/update path, deterministic resolver/planner, native and artifact execution, state/bundle/policy workflows, static site, tests, packaging, and release automation.
- **Key files changed:** `Cargo.toml`, `crates/`, `catalog/`, `schemas/`, `tests/`, `fuzz/`, `website/`, `docs/`, `packaging/`, `.github/`, and project documentation.
- **Decisions:** Kept resolution local and serverless, required typed plans and post-operation verification, used static TUF-style metadata, and kept production trust/signing owner-controlled.
- **Validation:** Passed formatting, strict Clippy, workspace/standalone/fuzz checks, schema/catalog/docs/site gates, RustSec and license/source policy checks, the local 10x p95 benchmark, and production-shaped local package verification.
- **Known limitations or blockers:** Native Windows/macOS execution and protected multi-platform CI were not run locally; production signing, notarization, and publication require repository-owner credentials.
- **Next starting point:** Run protected multi-platform CI and provision the documented production signing and publication secrets.
