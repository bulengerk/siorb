# Siorb

Siorb is a cross-platform CLI for managing software through the package manager already installed on the computer. It finds a compatible package, shows the exact plan, asks for consent, runs the native tool, and verifies the result.

It supports Windows, macOS, and Linux package managers including WinGet, Chocolatey, Scoop, Homebrew, APT, DNF, Pacman, Zypper, APK, Snap, and Flatpak. Resolution uses a bundled catalog and works without accounts, telemetry, a daemon, or a hosted service.

## Build and install

Install Git and Rust 1.85 with [rustup](https://rustup.rs/). Platform build requirements:

| Platform | Additional requirement |
|---|---|
| Linux | A C build toolchain such as `build-essential` |
| macOS | Xcode Command Line Tools: `xcode-select --install` |
| Windows | Visual Studio Build Tools with **Desktop development with C++** |

Clone and build on Linux, macOS, or Windows PowerShell:

```sh
git clone https://github.com/bulengerk/siorb.git
cd siorb
cargo build --release --locked -p siorb-cli
```

Run without installing:

```sh
cargo run --locked -p siorb-cli -- version
```

Install for the current user:

```sh
cargo install --path crates/siorb-cli --locked
siorb version
```

Cargo installs to `$HOME/.cargo/bin` on Linux/macOS and `%USERPROFILE%\.cargo\bin` on Windows. Signed releases can also provide `.deb`, `.rpm`, `.pkg`, `.msi`, `.zip`, and `.tar.gz` packages.

## Use

```sh
siorb search browser
siorb info firefox
siorb install firefox --dry-run --explain
siorb install firefox --yes
siorb doctor --json
```

Use `--dry-run` to preview changes. Use `--yes` only after reviewing the plan. Run `siorb --help` for every command and option.

## How it works

1. Detect the operating system, architecture, and available package managers.
2. Resolve the request from the local catalog and policy.
3. Produce an explainable, typed installation plan.
4. Execute only after consent, then verify and record the result.

## How it was created

Codex translated the project specification into a Rust workspace, package catalog, tests, documentation, packaging, website, and CI/release automation. Maintainers remain responsible for review and production signing.

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask verify
```

See `CONTRIBUTING.md` and `SECURITY.md` for contribution and security guidance.

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

### 2026-07-14 08:41 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Correct the CI expression scope for the safe temporary-directory setup.
- **Work completed:** Moved `TMPDIR` initialization from job-level expression context to a cross-platform runner setup step.
- **Key files changed:** `.github/workflows/ci.yml` and `README.md`.
- **Decisions:** Use the standard `RUNNER_TEMP` environment variable and `GITHUB_ENV`, which are available on every hosted runner.
- **Validation:** GitHub workflow dispatch parsing and repository verification follow this recorded entry.
- **Known limitations or blockers:** The refreshed workflow must be dispatched and complete on native macOS and Windows runners.
- **Next starting point:** Validate workflow parsing, push the correction, refresh Dependabot, and monitor the native matrix.

### 2026-07-14 14:53 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Expand the bundled catalog with high-value tools for software developers.
- **Work completed:** Added ten reviewed developer packages, regenerated runtime/TUF data and the static website, and made immutable signed fixtures compatible with monotonic catalog updates.
- **Key files changed:** `catalog/catalog.toml`, `catalog/packages/`, `catalog/fixtures/runtime-tuf/`, `catalog/verify-fixtures.mjs`, `catalog/{generated,index}.json`, `website/public/`, and `README.md`.
- **Decisions:** Accepted only confirmed native repository IDs, declared conservative architecture support, and kept the static signed TUF fixture immutable while rejecting schema drift and catalog rollback.
- **Validation:** Passed catalog generation, site generation, catalog/TUF gates, runtime search checks, workspace build, formatting, strict Clippy, and all workspace tests; full repository verification follows this entry.
- **Known limitations or blockers:** Package availability outside the explicitly reviewed platform and architecture mappings remains intentionally undeclared.
- **Next starting point:** Run final repository verification and review the complete generated diff before committing.

### 2026-07-14 14:57 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Publish the reviewed developer-tool catalog expansion to the main repository branch.
- **Work completed:** Prepared the package manifests, catalog metadata, runtime TUF fixtures, generated site, and verifier adjustment as one atomic change.
- **Key files changed:** `catalog/`, `website/public/`, and `README.md`.
- **Decisions:** Keep source manifests and all derived artifacts in the same commit so the bundled catalog and Pages output cannot drift.
- **Validation:** Workspace build, formatting, strict Clippy, workspace tests, catalog/TUF tests, runtime searches, and repository verification passed before publication; final verification follows this entry.
- **Known limitations or blockers:** The remote push remains pending until the verified commit is created.
- **Next starting point:** Run final verification, commit the complete catalog update, and push `main` to `origin`.

### 2026-07-14 18:51 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Replace the long project README with a concise English guide for users and developers.
- **Work completed:** Summarized the application's purpose, platform requirements, build, run, installation, basic usage, internal flow, and Codex-assisted creation process.
- **Key files changed:** `README.md`.
- **Decisions:** Use one shared cross-platform command path with short OS-specific prerequisites and keep the mandatory append-only work-session log physically final.
- **Validation:** Passed the documentation gate, including local links and all documented CLI command lines; full repository verification follows this entry.
- **Known limitations or blockers:** Native installer availability still depends on a signed release; source installation remains universally documented.
- **Next starting point:** Run final repository verification, then commit and publish the README update when requested.

### 2026-07-14 18:52 UTC — 019f5d0a-6e2c-7b73-a060-91c6dc9dcca2

- **Objective:** Publish the concise cross-platform README to the main repository branch.
- **Work completed:** Prepared the shortened English user and developer guide as a standalone documentation change.
- **Key files changed:** `README.md`.
- **Decisions:** Keep the simplified guide and its required append-only session record together in one documentation commit.
- **Validation:** Documentation and repository verification passed before publication; final repository verification follows this entry.
- **Known limitations or blockers:** The remote push remains pending until the documentation commit is created.
- **Next starting point:** Run final verification, commit the README update, and push `main` to `origin`.
