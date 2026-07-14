# Release process

Releases are prepared reproducibly without production secrets, then published
by the protected `release` GitHub environment. A tag does not bypass validation.
The release workflow builds from the tagged commit, creates archives/packages,
checksums, SBOM inputs, per-artifact provenance, an `ARTIFACTS.json` subject
manifest, hosted provenance attestations, and downstream metadata, then
publishes only after the environment's approval rules are satisfied.

Siorb is currently pre-1.0 and has no published production release. The commands
below describe the maintained release path; record actual results in
`FINAL_CHECKLIST.md` for each candidate.

## Preconditions

1. `CHANGELOG.md` has reviewed notes and no unsupported capability claim.
2. Version, tag `vMAJOR.MINOR.PATCH`, and catalog snapshot identity agree.
3. Required catalog metadata is unexpired for the intended publication window;
   checked-in roots are production roots and match the protected fingerprints.
4. CI, platform matrix, schema/catalog/docs tests, security policy, website
   generation, benchmarks, and the secret-free native DEB/RPM/MSI/PKG packaging
   matrix pass at the release commit.
5. No unresolved critical/high finding remains, or publication is stopped.
6. `FINAL_CHECKLIST.md` links the exact workflow runs/evidence.

Run locally:

```console
cargo xtask verify
cargo xtask test-schemas
cargo xtask test-catalog
cargo xtask test-docs
cargo xtask build-site
cargo xtask benchmark
cargo xtask release-local
```

`release-local` is a secret-free rehearsal. Inspect its artifact manifest,
checksums, archive contents, licenses, catalog snapshot, package metadata, and
version. It does not claim Authenticode, Apple notarization, or production
catalog threshold signatures.

Catalog role material is prepared separately from signing:

```console
cargo xtask prepare-catalog --artifacts dist/release-artifacts --out dist/catalog
cargo xtask sign-metadata --role targets --key /secure/path/targets.key --out dist/catalog
cargo xtask sign-metadata --role snapshot --key /secure/path/snapshot.key --out dist/catalog
cargo xtask sign-metadata --role timestamp --key /secure/path/timestamp.key --out dist/catalog
siorb catalog verify dist/catalog
```

`sign-metadata` reads one explicit key path, does not print private material, and
can be repeated for threshold signatures. Development fixture keys are valid
only for fixture roots and every resulting artifact must be marked non-production.
Root signing remains an offline ceremony and is never a routine CI step.

Release binary archives are TUF targets rather than a separate unsigned
self-update feed. Their target descriptions bind length, SHA-256, and custom
fields `kind = "siorb-binary"`, release version, normalized OS/architecture,
and archive format. `prepare-catalog --artifacts` creates these descriptions
before targets/snapshot/timestamp signing; the updater ignores a target lacking
the required typed metadata.

## Candidate and publication flow

1. Open a release PR updating version/changelog/generated material.
2. Obtain normal code, security-sensitive catalog, and packaging review.
3. Merge only after required checks and README session-log validation pass.
4. Create an annotated OpenPGP-signed maintainer tag: `git tag -s vX.Y.Z` and
   push the tag. Tag signing is a maintainer action; CI imports only the reviewed
   public keys and does not possess a Git signing key. The tagged commit must be
   reachable from protected `main` and the tag must match a protected tag
   ruleset.
5. The tag-triggered workflow validates that the tag version matches workspace
   metadata and changelog, then builds each platform from that commit.
6. The workflow signs/notarizes only when the protected environment exposes the
   documented secrets. Missing production signing material blocks a production
   release; it does not block a local candidate.
7. The workflow runs `cargo xtask package --verify dist` after creating the
   Cosign bundle. Review artifact names, `ARTIFACTS.json`, per-artifact
   provenance, SHA-256 manifest, SBOMs, signatures/bundles, attestations,
   catalog metadata, and generated package-manager manifests.
8. Approve publication in the `release` environment. Publish release notes from
   the reviewed changelog and mark pre-release state correctly.
9. Verify from a clean machine using downloaded artifacts and independent
   [checksum/signature instructions](release-verification.md). Test static
   catalog update without relying on repository checkout.
10. After a successful stable release, the Pages workflow downloads the
    immutable catalog ZIP, extracts it with path/type/size checks, verifies it
    through the runtime verifier, and publishes the complete static layout at
    `/catalog/`. Record evidence and announce the supported platform rows
    actually tested.

Pre-release tags publish signed native archives and catalog metadata but omit
DEB/RPM/MSI/PKG and WinGet/Homebrew submission material. This prevents package
ecosystems with incompatible version ordering from treating an `-rc` build as
the corresponding stable version.

## Production credentials

Never put these values in repository files, workflow inputs, logs, artifacts,
or pull-request environments:

| Secret/variable | Purpose | Scope |
|---|---|---|
| `SIORB_WINDOWS_PFX_BASE64` | base64 PKCS#12 Authenticode certificate/key | protected `release` environment |
| `SIORB_WINDOWS_PFX_PASSWORD` | PKCS#12 password | protected `release` environment |
| `SIORB_WINDOWS_TIMESTAMP_URL` | trusted timestamp service URL; repository variable is acceptable | release |
| `SIORB_APPLE_CERTIFICATE_P12_BASE64` | Developer ID Application/Installer material | protected `release` environment |
| `SIORB_APPLE_CERTIFICATE_PASSWORD` | PKCS#12 import password | protected `release` environment |
| `SIORB_APPLE_APPLICATION_IDENTITY` | expected Developer ID Application identity | protected environment variable |
| `SIORB_APPLE_INSTALLER_IDENTITY` | expected Developer ID Installer identity | protected environment variable |
| `SIORB_APPLE_ID` | notary account | protected `release` environment |
| `SIORB_APPLE_TEAM_ID` | Apple team ID | protected environment variable |
| `SIORB_APPLE_APP_PASSWORD` | app-specific notary password | protected `release` environment |
| `SIORB_CATALOG_TARGETS_KEY_BASE64` | online targets-role private key | separate catalog-signing environment |
| `SIORB_CATALOG_SNAPSHOT_KEY_BASE64` | online snapshot-role private key | separate catalog-signing environment |
| `SIORB_CATALOG_TIMESTAMP_KEY_BASE64` | online timestamp-role private key | separate catalog-signing environment |
| `SIORB_RELEASE_TAG_SIGNING_KEYS_BASE64` | base64 armored public OpenPGP keys accepted for release tags | repository variable |
| `SIORB_PRODUCTION_RUNTIME_ROOT_SHA256` | reviewed SHA-256 of `runtime-root.json` | repository/catalog-signing variable |
| `SIORB_PRODUCTION_TUF_ROOT_SHA256` | reviewed SHA-256 of `root.json` | repository/catalog-signing variable |

The two root fingerprints and release-tag public keys are public trust policy,
not secrets, but only repository/environment administrators may change their
configured values. The standard root must declare
`custom.environment = "production"`; release automation rejects the checked-in
deterministic development fixture even when its digest is supplied. The runtime
and standard serializations must authorize identical Ed25519 public material for
each role, with no key reuse across root, targets, snapshot, and timestamp.

Prefer GitHub OIDC keyless signing/attestation where the verifier policy accepts
it. Offline root keys never enter GitHub Secrets. Before first publication, the
owner must replace both development roots, configure the three public variables
above, provision applicable production credentials, protect `main` and the
release-tag pattern with repository rulesets, and restrict the `release` and
`catalog-signing` environments to reviewed refs and approvers.

## Signing boundaries

- SHA-256 checksums detect transfer errors but are not an authenticity signal by
  themselves.
- GitHub build provenance binds subjects to workflow identity and commit.
- Release signatures authenticate release files according to the documented
  verifier trust policy.
- Authenticode and Apple signing/notarization are platform distribution trust
  signals.
- TUF-style catalog role signatures protect catalog metadata and are verified
  independently of release signatures.

Do not reuse one key across these domains.

## Rollback and recovery

Never overwrite an existing release artifact or move a version tag. For a bad
binary, mark the release affected, remove it from recommended install channels
without destroying evidence, publish an advisory, and issue a higher patch
version. For a bad catalog target, publish new monotonically higher metadata
that removes/blocks it; clients' rollback protection intentionally prevents
serving older metadata as a fix. For key compromise, follow the root/role
rotation and incident runbooks.

## Reproducibility notes

Rust dependencies and toolchain are pinned, release profile settings reduce
variation, and workflow subjects are attested. Platform-native installers may
embed signing timestamps, notarization tickets, archive metadata, or toolchain
paths, so byte-for-byte reproducibility must be measured per artifact rather
than assumed. Compare unpacked binaries and SBOM/material sets, and document any
known nondeterministic field in release evidence.
