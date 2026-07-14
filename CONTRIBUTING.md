# Contributing to Siorb

Siorb turns package intent into native package-manager operations. A change can
therefore affect software supply-chain trust and host privileges. Small,
reviewable changes with explicit tests are preferred.

## Development setup

Install Git, Rust 1.85 or newer through `rustup`, Node.js 20 or newer for the
catalog/site generators, and Python 3.11 or newer for repository/release
validation. The checked-in Rust toolchain file selects the expected compiler
and components. Native DEB/RPM/MSI/PKG tools are optional unless changing those
outputs; CI exercises them on the corresponding host.

```console
git clone https://github.com/bulengerk/siorb.git
cd siorb
cargo build --workspace --all-features
cargo test --workspace --all-features
python3 -m pip install --requirement tests/requirements.txt
```

The default tests must not mutate the host or install packages. Tests that use a
real package manager must be opt-in and run in a disposable environment.

## Required checks

Run the checks relevant to the change, and run the complete set before opening
a release pull request:

```console
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask verify
cargo xtask test-schemas
cargo xtask test-catalog
cargo xtask generate-docs
cargo xtask test-docs
cargo xtask build-site
```

`cargo audit` and `cargo deny check` are CI gates. Install those tools only from
reviewed versions or use the security workflow.

## Change rules

- Keep resolution, planning, and execution separate. Do not invoke a backend
  before a plan has been produced and revalidated.
- Never build a shell command string from catalog data. Pass a validated
  executable and an argument vector to the process API.
- Do not add arbitrary lifecycle scripts to manifests or bundles.
- Treat aliases, URLs, archive paths, hashes, signer identities, policy rules,
  and package IDs as hostile input.
- Preserve stable reason codes, exit-code families, and versioned JSON schemas.
  An incompatible schema change requires a major release.
- Generated files carry a generation notice. Change their source, run the
  documented generator, and commit both source and output.
- Documentation must distinguish implemented behavior from a design contract
  or planned platform tier.

## Catalog changes

Read [catalog governance](docs/contributing/catalog-governance.md) and the
[manifest authoring guide](docs/contributing/manifest-authoring.md). A mapping
needs exact native IDs, upstream evidence, a review date, trust metadata, and
fixtures. Search matches may be fuzzy; install aliases may not be ambiguous.

Run:

```console
cargo xtask generate-catalog
cargo xtask test-catalog
cargo xtask build-site
python3 scripts/check_clean_tree.py catalog/generated website/public
```

The final command catches both modified tracked files and newly generated
untracked files, proving that the complete deterministic output was committed.

## Pull requests

Describe the behavior and threat impact, list actual validation, and identify
any platform not tested. Do not include credentials, production signing
material, private package indexes, or unredacted backend output. Security
vulnerabilities follow [SECURITY.md](SECURITY.md), not a public issue.

Every dependency or GitHub Action update must remain locked. GitHub Actions are
referenced by full commit SHA with a human-readable version comment.

## Codex work-session log

When Codex changes or meaningfully investigates the repository, it must append
one entry to the physically last `## Codex Work Sessions` section in
`README.md`. Earlier entries are immutable. The timestamp is UTC, the session
identifier is either one exposed by the interface or exactly
`Not exposed by the current Codex surface`, and all seven required fields must
be present. Run `cargo xtask verify`; it checks structure and that the target
branch's log is an unchanged prefix.

Human contributors do not fabricate Codex entries. If an earlier entry is
wrong, append a correction instead of editing history.

## Releases

Maintainers follow [the release runbook](docs/release-process.md). A tag alone
is not evidence that artifacts were signed or published; retain the protected
workflow run, attestations, checksums, and checklist evidence.
