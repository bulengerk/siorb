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

### 2026-07-14 07:28 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Restore the Pages pipeline and make Dependabot updates pass their repository checks.
- **Work completed:** Repaired the runtime-TUF hash fixture, Windows WiX variables, cross-platform Clippy issues, and Dependabot-safe security workflow behavior.
- **Key files changed:** `.github/workflows/security.yml`, `catalog/fixtures/runtime-tuf/`, `crates/siorb-{cli,executor,policy,state,update}/`, `packaging/windows/siorb.wxs`, and `scripts/release/test-packaging.sh`.
- **Decisions:** Retained Rust dependency policy checks for Dependabot, skipped unavailable GitHub-only review/CodeQL jobs for its read-only token, and used CodeQL's Rust `none` build mode.
- **Validation:** Passed native Linux tests and strict Clippy plus cross-target strict Clippy for Windows and macOS; catalog, site, packaging, and repository gates are queued below.
- **Known limitations or blockers:** GitHub Pages is currently disabled in repository settings and must be enabled with GitHub Actions as its source by a repository owner.
- **Next starting point:** Push these repairs, enable Pages if still disabled, then let Dependabot rebase and rerun its open updates.

### 2026-07-14 07:48 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Diagnose the remaining native Windows state-store checks on refreshed Dependabot pull requests.
- **Work completed:** Added failure-context output to the two state-store assertions that had previously hidden the underlying Windows error.
- **Key files changed:** `crates/siorb-cli/src/lib.rs` and `README.md`.
- **Decisions:** Kept the assertions strict while making failures actionable from GitHub Actions logs.
- **Validation:** Passed formatting, the CLI unit suite, and `cargo xtask verify` after recording this entry.
- **Known limitations or blockers:** A native Windows rerun is required to report and then resolve the remaining platform-specific initialization error.
- **Next starting point:** Push this diagnostic improvement, refresh a Dependabot branch, and inspect the native Windows test output.

### 2026-07-14 07:54 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Resolve the native Windows state-store ownership failure found on the refreshed Dependabot check.
- **Work completed:** Allowed the built-in Administrators SID as a trusted state-file owner and retained explicit current-user access checks.
- **Key files changed:** `crates/siorb-state/src/lib.rs` and `README.md`.
- **Decisions:** Accepted only the current user or the Administrators SID as owner; arbitrary groups and users remain rejected.
- **Validation:** Passed formatting, strict Windows-target Clippy for both MSVC architectures, and local `siorb-state` plus `siorb-cli` tests.
- **Known limitations or blockers:** The final native Windows rerun is still required after pushing this ownership adjustment.
- **Next starting point:** Push the adjustment, refresh Dependabot branches, and confirm both Windows MSVC matrices pass.

### 2026-07-14 07:58 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Prevent Dependabot pull requests from failing the human/Codex session-log contract.
- **Work completed:** Made the repository verifier exempt only Dependabot-authored pull requests from the new-session requirement.
- **Key files changed:** `crates/siorb-xtask/src/repository.rs` and `README.md`.
- **Decisions:** Read the pull-request author from GitHub's event payload rather than trusting the mutable workflow actor.
- **Validation:** Passed formatter, xtask unit tests, and strict xtask Clippy; full repository verification follows this entry.
- **Known limitations or blockers:** The exemption is intentionally limited to GitHub pull-request events whose author is exactly `dependabot[bot]`.
- **Next starting point:** Run full verification, push the verifier update, and refresh Dependabot branches.

### 2026-07-14 08:00 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Complete Dependabot verifier handling and expose the remaining Windows catalog-verification failure.
- **Work completed:** Added exact Dependabot event detection to xtask and actionable context to the signed-catalog test assertion.
- **Key files changed:** `crates/siorb-{cli,xtask}/src/` and `README.md`.
- **Decisions:** Preserve strict verification behavior while surfacing typed errors directly from the native CI log.
- **Validation:** Passed formatting plus focused CLI and xtask unit suites; full repository verification follows this entry.
- **Known limitations or blockers:** The final Windows catalog-verification error must be observed on the refreshed native runner.
- **Next starting point:** Run repository verification, push the changes, refresh the representative Dependabot branch, and repair the reported native error.

### 2026-07-14 08:06 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Repair the Windows TUF fixture byte mismatch and the portable packaging-smoke dependency failure.
- **Work completed:** Marked signed fixture trees as non-text in Git and replaced the PyYAML-only manifest assertion with a standard-library check.
- **Key files changed:** `.gitattributes`, `scripts/release/test-packaging.sh`, and `README.md`.
- **Decisions:** Treat all signed fixture bytes as immutable across checkout platforms and keep baseline CI tooling dependency-free.
- **Validation:** Passed fixture/catalog gates, CLI tests, packaging smoke test, formatting, and attribute checks; full repository verification follows this entry.
- **Known limitations or blockers:** Native Windows CI must rerun from a checkout containing the new attributes.
- **Next starting point:** Run full verification, push the fixes, refresh Dependabot, and confirm both Windows matrices plus repository gates.

### 2026-07-14 08:13 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Make the fake-backend E2E harness valid on every native platform.
- **Work completed:** Disabled the Unix text-fixture backend tests on Windows, where a text file cannot validly emulate a PE executable.
- **Key files changed:** `crates/siorb-cli/tests/e2e.rs` and `README.md`.
- **Decisions:** Retained native Windows catalog, state, CLI, and packaging coverage rather than treating an invalid fixture as a package manager.
- **Validation:** Passed formatting and the full local CLI E2E suite; native Windows rerun follows after this entry.
- **Known limitations or blockers:** Windows backend-invocation semantics require a real signed PE fixture and are not asserted by the portable text-fixture route.
- **Next starting point:** Run full verification, push the harness adjustment, refresh Dependabot, and confirm the native Windows matrix.

### 2026-07-14 08:18 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Repair the remaining native Windows Dependabot failure in planner tests.
- **Work completed:** Made the native-planner test fixture choose an absolute executable path and matching adapter for the target operating system.
- **Key files changed:** `crates/siorb-planner/src/lib.rs` and `README.md`.
- **Decisions:** Kept the production planner unchanged; the test now uses Chocolatey only on Windows and Apt elsewhere.
- **Validation:** Local planner tests and repository verification follow this recorded entry.
- **Known limitations or blockers:** Native Windows CI must rerun to confirm both MSVC architectures with the corrected fixture.
- **Next starting point:** Validate the planner fixture locally, push it, refresh Dependabot, and confirm the native Windows matrix.

### 2026-07-14 08:22 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Make Pages and Dependabot workflows deterministic with the pinned Rust toolchain.
- **Work completed:** Installed the `rustfmt` and `clippy` components before Cargo runs in CI project gates, Pages, and native packaging.
- **Key files changed:** `.github/workflows/{ci,pages,packaging}.yml` and `README.md`.
- **Decisions:** Preserve the pinned minimal toolchain while resolving the components explicitly instead of relying on Rustup's on-demand installation.
- **Validation:** Workflow syntax and repository verification follow this recorded entry.
- **Known limitations or blockers:** The GitHub-hosted project-gate retry and native Windows matrix are still required for final remote confirmation.
- **Next starting point:** Validate the workflow files, push the toolchain setup repair, refresh Dependabot, and monitor the remote gates.

### 2026-07-14 08:29 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Repair the macOS ARM test failure without weakening state-path link protections.
- **Work completed:** Moved state-store and CLI E2E test workspaces off macOS's `/var` symlinked temporary path.
- **Key files changed:** `crates/siorb-{cli,state}/` and `README.md`.
- **Decisions:** Kept production state-store symlink rejection strict; only test fixtures use canonical repository-local temporary directories on macOS.
- **Validation:** Local state and CLI tests plus repository verification follow this recorded entry.
- **Known limitations or blockers:** A native macOS ARM rerun is required to confirm the corrected test harness.
- **Next starting point:** Validate the portable test fixtures, push them, refresh Dependabot, and confirm all native CI matrices.

### 2026-07-14 08:33 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Eliminate the remaining macOS ARM executor test failures caused by temporary state paths.
- **Work completed:** Centralized executor test temporary-directory creation and use a canonical repository-local parent on macOS.
- **Key files changed:** `crates/siorb-executor/src/lib.rs` and `README.md`.
- **Decisions:** Apply the same fixture-only strategy across all executor state tests while preserving production symlink rejection.
- **Validation:** Local executor tests, lint, and repository verification follow this recorded entry.
- **Known limitations or blockers:** The native macOS ARM matrix must rerun to verify the centralized fixture on the hosted runner.
- **Next starting point:** Validate the executor suite locally, push it, refresh Dependabot, and confirm the full native matrix.

### 2026-07-14 08:37 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Repair the macOS ARM policy-loader fixture failure.
- **Work completed:** Made the policy-loader test create its private fixture under a canonical repository-local directory on macOS.
- **Key files changed:** `crates/siorb-policy/src/lib.rs` and `README.md`.
- **Decisions:** Retained strict policy parent-link rejection and moved only the positive test fixture away from macOS's system `/var` link.
- **Validation:** Local policy tests and repository verification follow this recorded entry.
- **Known limitations or blockers:** Native macOS ARM CI must rerun to confirm this final fixture adjustment.
- **Next starting point:** Validate, push, refresh Dependabot, and confirm the native macOS test matrix.

### 2026-07-14 08:39 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Make native CI temporary paths safe and deterministic across runner platforms.
- **Work completed:** Set the workspace-test `TMPDIR` to GitHub Actions' runner-managed temporary directory.
- **Key files changed:** `.github/workflows/ci.yml` and `README.md`.
- **Decisions:** Keep application-level link defenses unchanged while ensuring test fixtures never inherit macOS's `/var` symlinked temporary root.
- **Validation:** YAML and repository verification follow this recorded entry.
- **Known limitations or blockers:** The refreshed native matrix must complete to provide final hosted-runner confirmation.
- **Next starting point:** Push this CI environment adjustment, refresh Dependabot, and confirm all matrix jobs.
