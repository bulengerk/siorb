# Siorb

Siorb is a cross-platform CLI for managing software through the package manager already installed on the computer. It finds a compatible package, shows the exact plan, asks for consent, runs the native tool, and verifies the result.

It supports Windows, macOS, and Linux package managers including WinGet, Chocolatey, Scoop, Homebrew, APT, DNF, Yum, Pacman, Zypper, APK, Snap, and Flatpak. Resolution uses a bundled catalog and works without accounts, telemetry, a daemon, or a hosted service.

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

### 2026-07-18 05:20 UTC — Not exposed by the current Codex surface

- **Objective:** Repair failing GitHub pipelines and prove that packaged Siorb is usable on native Windows and macOS runners.
- **Work completed:** Corrected Windows hardlink handling, made catalog evidence probes distinguish broken links from transient provider failures, added probe regression tests, and expanded the opt-in native smoke workflow to install and exercise MSI and PKG builds.
- **Key files changed:** `.github/workflows/catalog-health.yml`, `.github/workflows/native-smoke.yml`, `crates/siorb-xtask/src/repository.rs`, `scripts/catalog/`, `scripts/release/package-windows.ps1`, `scripts/release/authenticode-sign.ps1`, and `README.md`.
- **Decisions:** Continue rejecting Windows reparse points while accepting ordinary Cargo hardlinks, serialize evidence probes per host, fail only on actionable catalog findings, and keep host mutation confined to an explicitly dispatched disposable-runner workflow.
- **Validation:** Passed catalog-probe unit tests, Python compilation, formatting, workflow lint where available, diff checks, and local search, info, and dry-run planning smoke tests.
- **Known limitations or blockers:** Native package creation, installation, and package-manager mutation still require the updated workflows to run on GitHub-hosted Windows and macOS machines.
- **Next starting point:** Complete repository gates, publish the changes, dispatch the packaging and native mutation workflows, and repair any native-only failures they expose.

### 2026-07-18 05:22 UTC — Not exposed by the current Codex surface

- **Objective:** Complete the local quality gates for the cross-platform pipeline repairs before publishing them.
- **Work completed:** Exercised the entire all-feature workspace build, strict lint suite, unit, integration, end-to-end, documentation, schema, packaging, and repository checks against the repaired workflow and helper code.
- **Key files changed:** `README.md` records this validation checkpoint; the validated implementation remains in `.github/workflows/`, `crates/siorb-xtask/`, and `scripts/`.
- **Decisions:** Treat native hosted-runner results as the remaining authority for MSI, PKG, WinGet, and Homebrew behavior while requiring all deterministic local gates to pass first.
- **Validation:** Passed `cargo build --workspace --all-features`, strict workspace Clippy, all-feature workspace tests, and `cargo xtask verify`; a throttled live catalog-evidence probe is still running independently.
- **Known limitations or blockers:** Linux cannot execute the native PowerShell, WiX, macOS packaging, WinGet, or Homebrew paths, so those paths remain pending remote validation.
- **Next starting point:** Inspect the completed live health report, review the diff, commit and push, then monitor all native GitHub jobs.

### 2026-07-18 05:25 UTC — Not exposed by the current Codex surface

- **Objective:** Make the repaired catalog-health probe both provider-friendly and fast enough for the scheduled workflow.
- **Work completed:** Interleaved evidence URLs across hostnames before parallel execution so per-host serialization no longer starves unrelated providers, and added a deterministic scheduling regression test.
- **Key files changed:** `scripts/catalog/catalog_health.py`, `scripts/catalog/test_catalog_health.py`, and `README.md`.
- **Decisions:** Preserve one in-flight request per evidence host while using the existing global worker pool across independent hosts.
- **Validation:** Passed all five catalog-probe unit tests, formatting, diff checks, workflow lint where available, and restarted a complete live 682-URL probe.
- **Known limitations or blockers:** The live probe is network-bound and still running; remote GitHub-hosted validation remains pending publication.
- **Next starting point:** Finish the live probe, inspect warnings versus actionable findings, then publish and run the native workflows.

### 2026-07-18 05:27 UTC — Not exposed by the current Codex surface

- **Objective:** Ensure the Windows usability workflow cannot hide an early native CLI failure behind a later successful command.
- **Work completed:** Enabled strict native-command exit handling for the installed Siorb discovery, planning, and WinGet transaction step.
- **Key files changed:** `.github/workflows/native-smoke.yml` and `README.md`.
- **Decisions:** Require every PowerShell-launched Siorb invocation to fail the job immediately on a nonzero exit code.
- **Validation:** Re-reviewed the complete workflow diff, retained the passing local repository gates, and continued the provider-throttled live evidence probe.
- **Known limitations or blockers:** Native PowerShell execution and package installation remain pending the GitHub-hosted Windows run.
- **Next starting point:** Complete live health validation, rerun repository checks, publish, and inspect native job logs command by command.

### 2026-07-18 05:29 UTC — Not exposed by the current Codex surface

- **Objective:** Resolve the actionable catalog failures exposed by the repaired live evidence check.
- **Work completed:** Updated six renamed or tap-hosted Homebrew mappings and evidence URLs for Bun, Docker Desktop, HandBrake, kubectl, Python, and Terraform, then regenerated the catalog, runtime TUF fixtures, and package website.
- **Key files changed:** `catalog/packages/{bun,docker,handbrake,kubectl,python,terraform}.toml`, generated `catalog/` fixtures and indexes, corresponding `website/public/` package pages, and `README.md`.
- **Decisions:** Use current canonical Homebrew tokens where available and explicit upstream tap identities for Bun and Terraform instead of dead formulae-site URLs.
- **Validation:** Confirmed the replacement sources against current Homebrew APIs and upstream tap repositories; catalog validation, generation, runtime fixture generation, site generation, and site validation passed.
- **Known limitations or blockers:** A second full live evidence pass and native GitHub runner validation are still required before publication can be considered complete.
- **Next starting point:** Re-run the complete catalog health probe, execute final repository gates, then commit, push, and monitor the workflows.

### 2026-07-18 05:31 UTC — Not exposed by the current Codex surface

- **Objective:** Revalidate the complete workspace after regenerating the corrected Homebrew catalog data.
- **Work completed:** Rebuilt and linted every workspace target, reran all all-feature tests, verified the catalog and adversarial runtime TUF fixtures, and rebuilt and validated the static site.
- **Key files changed:** `README.md` records the post-regeneration validation checkpoint; no additional implementation files changed in this step.
- **Decisions:** Require catalog cryptographic attack fixtures and all workspace consumers to pass after mapping changes, not only the manifest linter.
- **Validation:** Passed workspace build, formatting, strict Clippy, all-feature tests, `cargo xtask test-catalog`, and `cargo xtask build-site`.
- **Known limitations or blockers:** The second full live 682-URL evidence probe is still running, followed by native hosted-runner execution.
- **Next starting point:** Inspect the final health report, run the final repository verifier, publish, and monitor GitHub Actions.

### 2026-07-18 05:31 UTC — Not exposed by the current Codex surface

- **Objective:** Confirm catalog health after the mapping repairs and prepare the complete pipeline fix for publication.
- **Work completed:** Completed a provider-throttled live check of all 682 evidence URLs and reviewed the resulting actionable and informational classifications.
- **Key files changed:** `README.md` records the successful live validation; the implementation and regenerated catalog diff are ready for commit.
- **Decisions:** Preserve 429 and 403 probe results as report warnings while requiring zero stale, unsafe, invalid, 404, or 410 findings for a healthy result.
- **Validation:** The final report is healthy with zero findings across 130 manifests and 682 unique evidence URLs; 124 provider-limit warnings remain visible in the machine-readable report.
- **Known limitations or blockers:** Native MSI, PKG, WinGet, and Homebrew execution still require the post-push GitHub-hosted workflows.
- **Next starting point:** Run final repository verification, commit and push the complete change, then monitor and repair all native runs to green.

### 2026-07-18 05:33 UTC — Not exposed by the current Codex surface

- **Objective:** Publish the verified pipeline repair and start native Windows and macOS validation.
- **Work completed:** Committed and pushed the complete change as `3bcb9ec`, then dispatched the catalog-health and disposable native mutation workflows alongside the automatically triggered CI, packaging, catalog, site, and security runs.
- **Key files changed:** `README.md` records publication and dispatch status; the implementation was published in commit `3bcb9ec`.
- **Decisions:** Validate the pushed main-branch commit on hosted runners before making any further platform-specific adjustment.
- **Validation:** GitHub accepted the push and queued seven workflows for the published commit, including native MSI/PKG packaging and opt-in WinGet/Homebrew mutation tests.
- **Known limitations or blockers:** Hosted jobs are currently queued or running; native usability is not yet confirmed until their logs complete successfully.
- **Next starting point:** Monitor every job, inspect the first native failure if any, and iterate until all required workflows are green.

### 2026-07-18 05:39 UTC — Not exposed by the current Codex surface

- **Objective:** Repair the platform-specific failures found by the first disposable Windows and macOS usability run.
- **Work completed:** Made MSI installation and removal synchronous with verbose diagnostics and native Program Files discovery, expanded the reviewed Homebrew contract through major version 6, and updated macOS detector fixtures and support documentation for the runner's Homebrew 6.0.11.
- **Key files changed:** `.github/workflows/native-smoke.yml`, `crates/siorb-platform/src/lib.rs`, `docs/platform-support.md`, macOS platform fixtures and goldens, and `README.md`.
- **Decisions:** Keep the backend version gate bounded at `<7` while accepting the currently exercised Homebrew major versions 4 through 6; retain explicit opt-in for every host-mutating smoke test.
- **Validation:** The original published commit passed CI, security, catalog validation, site deployment, catalog health, and every native packaging job; focused platform unit and golden-fixture tests pass with Homebrew 6.0.11, and the edited workflow parses as YAML.
- **Known limitations or blockers:** The repaired disposable native mutation workflow has not yet been rerun on GitHub-hosted Windows and macOS runners.
- **Next starting point:** Run every repository gate, publish the native follow-up, and repeat the installed MSI, PKG, WinGet, and Homebrew transactions.

### 2026-07-18 05:42 UTC — Not exposed by the current Codex surface

- **Objective:** Publish and monitor the repaired native usability validation.
- **Work completed:** Committed and pushed the follow-up as `e2bee95`, dispatched the opt-in native mutation workflow, and confirmed that its Windows, macOS, and Linux jobs started on the intended hosted runners.
- **Key files changed:** `README.md` records the active hosted-runner validation; the implementation is published in commit `e2bee95`.
- **Decisions:** Keep the test focused on installed package behavior and real package-manager transactions rather than treating successful compilation as usability proof.
- **Validation:** All local repository gates passed before publication; the new native jobs checked out the exact published commit and began native builds successfully.
- **Known limitations or blockers:** MSI/PKG installation and WinGet/Homebrew transaction steps are still running.
- **Next starting point:** Continue monitoring each command-level result and repair any remaining native-only failure before declaring the pipelines usable.

### 2026-07-18 05:44 UTC — Not exposed by the current Codex surface

- **Objective:** Resolve the remaining Windows usability failure without reducing platform coverage.
- **Work completed:** Confirmed that MSI installation, the installed Windows ARM64 CLI, offline search and info, macOS PKG installation, and the full Homebrew transaction all succeed; moved the WinGet mutation test from the preview Windows 11 ARM image, which does not expose WinGet, to the generally available Windows Server 2025 x64 image and selected the matching x64 MSI.
- **Key files changed:** `.github/workflows/native-smoke.yml` selects the GA Windows 2025 x64 runner and package architecture; `README.md` records the runner-specific diagnosis.
- **Decisions:** Exercise WinGet on a GitHub-supported x64 Windows 2025 runner while retaining separate CI and packaging coverage for Windows ARM64.
- **Validation:** The second native run passed macOS PKG plus Homebrew end to end and Linux APT end to end; its Windows job passed build, MSI creation, MSI installation, installed CLI startup, catalog search, catalog info, MSI removal, and failed only when the absent WinGet backend was requested.
- **Known limitations or blockers:** The revised Windows 2025 WinGet transaction still requires one hosted rerun.
- **Next starting point:** Verify workflow syntax and repository invariants, publish the runner adjustment, then rerun Windows installation, planning, WinGet install, verification, removal, and MSI cleanup.

### 2026-07-18 05:45 UTC — Not exposed by the current Codex surface

- **Objective:** Publish the GA Windows runner adjustment and execute the final native usability rerun.
- **Work completed:** Committed and pushed the runner correction as `d1e38d6`, dispatched the native mutation workflow, and confirmed that Windows 2025 x64, macOS 15 ARM64, and Ubuntu 24.04 jobs started from that commit.
- **Key files changed:** `README.md` records publication and dispatch status; the workflow correction is published in commit `d1e38d6`.
- **Decisions:** Use the explicit `windows-2025` label instead of a floating or preview runner label for WinGet usability coverage.
- **Validation:** Workflow YAML and full repository verification passed immediately before publication; all three new jobs completed checkout and entered native toolchain or build steps.
- **Known limitations or blockers:** The final hosted MSI, WinGet, PKG, Homebrew, and APT transaction results are still pending.
- **Next starting point:** Monitor the command-level results to completion, then record and publish the final evidence if every native mutation succeeds.

### 2026-07-18 05:47 UTC — Not exposed by the current Codex surface

- **Objective:** Track the final native usability run through real package-manager mutations.
- **Work completed:** Observed the macOS and Linux jobs finish successfully on the final workflow revision while the Windows 2025 x64 job continued its native release build.
- **Key files changed:** `README.md` records the hosted-runner checkpoint; no implementation files changed during monitoring.
- **Decisions:** Wait for the slower Windows native build and require its complete MSI and WinGet transaction rather than inferring success from the already-green package matrix.
- **Validation:** macOS again passed PKG installation, installed CLI checks, Homebrew install, verification, removal, and package cleanup; Linux again passed the APT install, verification, and removal cycle.
- **Known limitations or blockers:** Windows 2025 has not yet reached its MSI and WinGet steps.
- **Next starting point:** Continue monitoring Windows through MSI installation, installed CLI discovery, WinGet mutation, verification, removal, and cleanup.

### 2026-07-18 05:49 UTC — Not exposed by the current Codex surface

- **Objective:** Make the disposable Windows usability test self-contained on clean hosted runner images.
- **Work completed:** Confirmed the Windows 2025 MSI and installed CLI work but that the ephemeral server image does not register WinGet for the runner account, then added Microsoft's documented WinGet repair bootstrap with the Microsoft module pinned to version 1.29.280 and exported the resolved executable directory explicitly.
- **Key files changed:** `.github/workflows/native-smoke.yml` bootstraps and verifies WinGet before building Siorb; `README.md` records the clean-image prerequisite diagnosis.
- **Decisions:** Provision the missing OS package-manager prerequisite from Microsoft's PowerShell Gallery using an exact module version instead of weakening Siorb's backend availability checks or substituting a mock.
- **Validation:** The third native run again passed macOS and Linux end to end; Windows 2025 passed build, x64 MSI creation, synchronous MSI installation, installed CLI startup, catalog search and info, MSI removal, and failed only because the clean image had no registered WinGet executable.
- **Known limitations or blockers:** The pinned WinGet bootstrap and subsequent real transaction still need hosted-runner execution.
- **Next starting point:** Verify the workflow and repository, publish the self-contained test, then rerun the complete Windows MSI and WinGet sequence.

### 2026-07-18 05:51 UTC — Not exposed by the current Codex surface

- **Objective:** Make the pinned WinGet bootstrap compatible with the hosted runner's PowerShell 7 environment.
- **Work completed:** Replaced the legacy NuGet package-provider bootstrap, which is unsupported in the runner's PowerShell 7 session, with the current `Install-PSResource` flow while preserving the exact Microsoft.WinGet.Client 1.29.280 version and trusted PSGallery selection.
- **Key files changed:** `.github/workflows/native-smoke.yml` uses PowerShell PSResourceGet; `README.md` records the bootstrap compatibility repair.
- **Decisions:** Use the native PowerShell 7 resource installer documented for current PowerShell instead of switching the workflow to a legacy shell or allowing an unpinned module version.
- **Validation:** The failing hosted log shows the obsolete `Install-PackageProvider NuGet` call was the only command reached and failed before any module or host mutation; the replacement retains exact source, version, and scope controls.
- **Known limitations or blockers:** The PSResourceGet installation and WinGet repair sequence still require hosted execution.
- **Next starting point:** Validate repository invariants, cancel the superseded failing run, publish the PowerShell 7 bootstrap, and rerun the native workflow.

### 2026-07-18 05:52 UTC — Not exposed by the current Codex surface

- **Objective:** Confirm that the self-contained Windows prerequisite bootstrap works before the final native transaction.
- **Work completed:** Committed and pushed the PowerShell 7 correction as `8238db1`, dispatched a fresh native workflow, and observed the Windows 2025 job complete the pinned PSResourceGet module installation, WinGet repair, executable discovery, and version probe successfully.
- **Key files changed:** `README.md` records the hosted bootstrap success; the executable workflow is published in commit `8238db1`.
- **Decisions:** Keep the now-proven pinned bootstrap and continue through the unchanged real Siorb transaction rather than adding any runner-specific bypass.
- **Validation:** The Windows job's `Bootstrap stable WinGet on the disposable runner` step is green and the job advanced to the native Siorb build; Linux and macOS builds are running in parallel.
- **Known limitations or blockers:** The final MSI install and Siorb-driven WinGet install, verify, and remove steps remain in progress.
- **Next starting point:** Monitor the Windows build and package steps through the complete transaction and cleanup, then publish the final result log.

### 2026-07-18 05:54 UTC — Not exposed by the current Codex surface

- **Objective:** Hold the final native workflow to complete cross-platform usability evidence.
- **Work completed:** Observed the final macOS and Linux jobs complete successfully again while the Windows job continued its release build after the now-green WinGet bootstrap.
- **Key files changed:** `README.md` records the latest hosted-runner checkpoint; no implementation files changed during monitoring.
- **Decisions:** Retain the complete three-platform mutation workflow and wait for Windows rather than treating the successful prerequisite bootstrap as the final result.
- **Validation:** macOS passed installed PKG behavior and the Homebrew transaction; Linux passed the APT transaction; Windows passed checkout, toolchain setup, and pinned WinGet bootstrap.
- **Known limitations or blockers:** Windows is still compiling Siorb before MSI creation and the real WinGet transaction.
- **Next starting point:** Monitor Windows through build, WiX packaging, MSI installation, Siorb planning, WinGet install, verification, removal, and MSI cleanup.

### 2026-07-18 05:57 UTC — Not exposed by the current Codex surface

- **Objective:** Expose the repaired WinGet executable to Siorb as a normal validated backend path.
- **Work completed:** Confirmed that the pinned WinGet repair succeeds and launches version 1.11.510 but that its per-user App Execution Alias is not accepted as a regular executable by Siorb's path validation, then changed the smoke bootstrap to resolve the registered Microsoft.DesktopAppInstaller package and export its native installation directory.
- **Key files changed:** `.github/workflows/native-smoke.yml` resolves the registered AppX package's real `winget.exe`; `README.md` records the alias-versus-native-path diagnosis.
- **Decisions:** Preserve Siorb's canonical regular-file requirement and provide the actual Microsoft package executable path instead of weakening executable validation for reparse-point aliases.
- **Validation:** The latest Windows run passed WinGet repair, version execution, Siorb build, WiX setup, x64 MSI creation, synchronous MSI installation, installed CLI startup, catalog search and info, and MSI cleanup; Siorb rejected only the alias-backed WinGet path before any package mutation.
- **Known limitations or blockers:** The native AppX installation path and subsequent Siorb-driven WinGet transaction require one more hosted execution.
- **Next starting point:** Verify and publish the native-path correction, then rerun the final Windows install, verify, remove, and cleanup sequence.

### 2026-07-18 06:07 UTC — Not exposed by the current Codex surface

- **Objective:** Confirm real Windows and macOS usability on the published native-path correction.
- **Work completed:** Published commit `6c6f5f5` and completed the disposable three-platform workflow with every job green, including installed package execution and real package-manager mutations.
- **Key files changed:** `README.md` records the successful hosted evidence; the final native workflow implementation is published in commit `6c6f5f5`.
- **Decisions:** Treat usability as proven only after successful native package installation, installed CLI discovery and planning, package-manager mutation, post-mutation verification, removal, and package cleanup.
- **Validation:** Windows 2025 x64 passed pinned WinGet 1.11.510 bootstrap, MSI build/install, Siorb search/info/dry-run, real `hyperfine` install/verify/remove through WinGet, and MSI uninstall; macOS 15 ARM64 passed the equivalent PKG and Homebrew cycle; Ubuntu passed APT install/verify/remove. CI and all Windows/macOS/Linux packaging jobs are green on the same commit.
- **Known limitations or blockers:** The Security workflow on the final implementation commit is still finishing CodeQL and Rust policy jobs.
- **Next starting point:** Wait for Security to finish, record the complete green pipeline set, verify the final work-session log, and publish the closing documentation commit.

### 2026-07-18 06:09 UTC — Not exposed by the current Codex surface

- **Objective:** Close the pipeline repair with a complete green implementation commit and durable evidence.
- **Work completed:** Monitored the final Security jobs to completion and reviewed the Windows transaction log command by command, confirming resolution to the WinGet source, successful mutation, committed receipt state, verification, absence verification after removal, and MSI cleanup.
- **Key files changed:** `README.md` records the final validation outcome; no implementation files changed after commit `6c6f5f5` passed its workflows.
- **Decisions:** Preserve the explicit opt-in native mutation workflow and its real host changes as the usability gate while keeping normal CI and packaging non-mutating.
- **Validation:** On `6c6f5f5`, CI, Security, Native packaging, and Disposable native mutation smoke all completed successfully; the earlier final catalog-health, catalog validation/signing, and site deployment workflows also completed successfully after the catalog repair.
- **Known limitations or blockers:** Production release signing, Apple notarization, and external package-repository publication still require repository credentials and a release event; unsigned disposable-runner packages and runtime behavior are verified.
- **Next starting point:** Publish this immutable closing entry, confirm the documentation-only head remains green, then create a signed release when release credentials are available.

### 2026-07-19 09:28 UTC — Not exposed by the current Codex surface

- **Objective:** Expand Siorb's mainstream Linux package-manager coverage with a complete Yum backend.
- **Work completed:** Added reviewed Yum detection for the Fedora/RHEL family, typed install/remove/update/reinstall/query argument vectors, bounded installed-version parsing, policy and schema support, 89 Yum catalog mappings derived from the existing reviewed DNF package identities, regenerated catalog/TUF/site outputs, and added a disposable Rocky Linux mutation job.
- **Key files changed:** `crates/siorb-backends`, `crates/siorb-platform`, `crates/siorb-resolver`, catalog manifests/schemas/policies/generated outputs, `.github/workflows/native-smoke.yml`, backend fixtures, platform documentation, and this README.
- **Decisions:** Treat Yum as a distinct selectable backend while preferring modern DNF when both are available; keep package identifiers as separate validated arguments; support reviewed Yum 3.4 through 4.x behavior; pin the Rocky Linux smoke image by digest; do not model low-level RPM or DPKG commands as dependency-resolving managers.
- **Validation:** Catalog generation and site validation pass with 130 packages and 776 mappings; Yum adapter, query parser, RHEL-family detector, explicit resolver selection, captured-output security tests, full workspace build, formatting, strict Clippy, and all workspace tests pass.
- **Known limitations or blockers:** This host has no Docker, Yum, or DNF executable, so the real Rocky Linux `git` install/verify/remove cycle remains pending on the explicit hosted native-smoke workflow.
- **Next starting point:** Run `cargo xtask verify` with this required immutable entry, review the final diff, publish the implementation, and dispatch the opt-in Rocky Linux native mutation smoke.

### 2026-07-19 09:30 UTC — Not exposed by the current Codex surface

- **Objective:** Publish the Yum implementation and start real hosted package-manager validation.
- **Work completed:** Committed the complete backend, catalog, generated-site, documentation, and workflow update as `1d1a85a`, pushed it to `main`, and dispatched disposable native mutation run `29681686594` on that exact implementation commit.
- **Key files changed:** The implementation commit contains the reviewed project changes; this follow-up changes only the physically final README work-session log.
- **Decisions:** Require the new Rocky Linux job to complete the same discovery, dry-run, real install, verification, removal, and cleanup standard as the existing APT, Homebrew, and WinGet jobs.
- **Validation:** All local repository and contract gates passed before publication; GitHub accepted the workflow dispatch and queued all native jobs from `1d1a85a`.
- **Known limitations or blockers:** Hosted Rocky Linux Yum, Ubuntu APT, macOS Homebrew, and Windows WinGet mutation results are still pending.
- **Next starting point:** Verify and publish this immutable checkpoint, then monitor run `29681686594` through every native transaction before claiming hosted Yum usability.

### 2026-07-19 09:32 UTC — Not exposed by the current Codex surface

- **Objective:** Monitor the first hosted four-manager mutation run without leaving a background watcher behind.
- **Work completed:** Confirmed all four jobs started, stopped the local `gh run watch` process after taking a bounded snapshot, and observed Windows complete its pinned WinGet bootstrap while macOS completed the Siorb build and PKG installation.
- **Key files changed:** Only this immutable README monitoring entry is new; the hosted jobs continue on implementation commit `1d1a85a`.
- **Decisions:** Keep the real Yum transaction as the acceptance criterion and use bounded status checks instead of a persistent local background terminal.
- **Validation:** Rocky Linux completed checkout plus the pinned toolchain/musl setup and entered the portable build; Ubuntu entered its build; Windows entered its Siorb build after WinGet bootstrap; macOS entered the Homebrew transaction step after package installation.
- **Known limitations or blockers:** No native job has failed, but the Yum, APT, Homebrew, and WinGet mutation steps have not all completed yet.
- **Next starting point:** Continue bounded polling of run `29681686594`, inspect any failed command directly, and record final evidence only after all four jobs finish.

### 2026-07-19 09:35 UTC — Not exposed by the current Codex surface

- **Objective:** Repair the Rocky Linux Yum smoke precondition without weakening Siorb's privilege model.
- **Work completed:** Reviewed the completed hosted run, confirmed Windows WinGet, macOS Homebrew, and Ubuntu APT all passed their native end-to-end transactions, traced the Yum failure to the minimal Rocky image lacking a supported privilege broker, and added a one-time Yum bootstrap of the trusted `sudo` package inside the disposable container.
- **Key files changed:** `.github/workflows/native-smoke.yml` provisions the broker before invoking Siorb; `README.md` records the diagnosis and completed cross-platform results.
- **Decisions:** Keep Siorb's per-step privilege-broker requirement intact even when the disposable container starts as root; bootstrap `/usr/bin/sudo` through Yum instead of adding a direct-root execution bypass.
- **Validation:** Run `29681686594` proves Windows MSI plus WinGet, macOS PKG plus Homebrew, and Ubuntu APT are usable; its Rocky log proves explicit resolution to `git-yum` and the correct typed `/usr/bin/dnf-3 install -y -- git` plan before refusing mutation because no broker existed.
- **Known limitations or blockers:** The workflow fix still needs local repository verification, publication, and a fresh hosted Rocky transaction.
- **Next starting point:** Run the required verification gates, publish the workflow repair, and dispatch a fresh bounded native-smoke run.

### 2026-07-19 09:36 UTC — Not exposed by the current Codex surface

- **Objective:** Publish the Rocky/Yum broker fix and start fresh native acceptance testing.
- **Work completed:** Passed the full local build, formatting, strict Clippy, workspace tests, and repository verification gates; committed and pushed the workflow repair as `afcddda`; dispatched native-smoke run `29681835090` on that exact commit.
- **Key files changed:** The published commit updates `.github/workflows/native-smoke.yml` and preserves both immutable hosted-validation entries in `README.md`; this entry records the new run.
- **Decisions:** Judge the repair on a fresh commit-specific run while retaining the first failed run as diagnostic evidence and using bounded API checks instead of a persistent terminal watcher.
- **Validation:** Local repository verification reports 130 packages, 776 mappings, 158 aliases, 3 policies, current generated catalog/site outputs, and passing schema, packaging, security, and Rust gates; GitHub accepted the new native-smoke dispatch.
- **Known limitations or blockers:** Run `29681835090` is queued and has not yet proven the repaired Rocky/Yum mutation path.
- **Next starting point:** Verify this required log entry, publish it, then inspect all four native jobs through completion with special attention to Yum install, query, receipt, and removal evidence.
