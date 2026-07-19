# Catalog manifest format v1

Human-reviewed package manifests are TOML files under `catalog/packages/`.
`cargo xtask generate-catalog` sorts and combines them into
`catalog/generated/catalog.json`; the generated file is embedded by the CLI and
must not be hand-edited. `siorb-catalog`'s Rust types and catalog tests are the
normative parser; this document explains their v1 surface.

```toml
schema_version = "1"
id = "example-tool"
name = "Example Tool"
description = "A concise statement of what the package provides."
aliases = ["example"]
deprecated_aliases = []
search_terms = ["utility"]
homepage = "https://example.invalid/"
upstream = "example/example-tool"
license = "Apache-2.0"
risk = "standard"
categories = ["developer-tools"]
capabilities = ["cli"]
channels = ["stable"]
conflicts = []
replacements = []
dependencies = []
optional_relationships = []
version_normalization = "semver"
verification = "backend-signature"
evidence = ["https://example.invalid/install"]
reviewed_at = "2026-07-13"
maintainers = ["siorb-maintainers"]
deprecated = false

[[sources]]
id = "example-tool-apt"
platform = "debian"
distributions = ["debian", "ubuntu"]
backend = "apt"
package_id = "example-tool"
trust = "native"
scope = "system"
channel = "stable"
architectures = ["x86_64", "aarch64"]
priority = 100
requires_privilege = true
provenance = "backend-repository"
evidence = "https://packages.debian.org/example-tool"
reviewed_at = "2026-07-13"
```

The `.invalid` example is intentionally non-installable and must not be copied
into the production catalog.

## Package fields

| Field | Meaning |
|---|---|
| `schema_version` | Repository manifest contract; v1 is exactly `"1"` |
| `id` | Stable canonical logical ID |
| `name`, `description` | Display/search text; both non-empty |
| `aliases` | Exact install identities in addition to `id` |
| `deprecated_aliases` | Exact identities that resolve with a deprecation signal |
| `search_terms` | Search-only terms; never exact install aliases |
| `homepage`, `upstream`, `license` | Project identity and SPDX-style license evidence |
| `risk` | Review classification, not a guarantee of safety |
| `categories`, `capabilities` | Policy/search metadata |
| `channels` | Channels represented by sources |
| relationship arrays | Logical IDs for conflicts/replacements/dependencies/optional relationships |
| `version_normalization` | Named normalization rule used for comparisons |
| `verification` | Package-level verification summary |
| `evidence`, `reviewed_at`, `maintainers` | Review provenance/ownership |
| `deprecated` | Prevents presenting the package as a normal current choice |
| `sources` | One or more platform/native candidates |

Repository manifests use lowercase ASCII alphanumeric segments separated by a
single `-` and cannot shadow a command. Runtime normalization additionally
enforces a bounded safe ASCII identifier grammar before lookup. Aliases are
validated against the manifest grammar and cannot collide with any other
canonical/alias identity. Unicode confusables therefore cannot become install
identities. Search can normalize broader input, but fuzzy results never
authorize installation.

## Source fields

`sources.id` is globally unique. `platform` is one of `windows`, `macos`,
`linux`, `debian`, `fedora`, `arch`, `opensuse`, or `alpine`. Current backend
identifiers are `winget`, `scoop`, `chocolatey`, `homebrew-formula`,
`homebrew-cask`, `macports`, `apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`, `flatpak`,
`snap`, and `artifact`.

`package_id` is the exact native ID; option-like IDs and control characters are
invalid. `trust` is `native`, `sandboxed`, or `verified-upstream`; `scope` is
`user`, `system`, or `auto`; `channel` is `stable`, `beta`, or `nightly`.
`priority` participates only after hard compatibility/policy filters. Higher
priority cannot override policy or verification.

Every source needs an evidence URL and review date. The validator proves field
shape and collisions; governance review must additionally verify that the exact
native ID exists at that evidence, publisher/upstream identity matches, scope
and privilege are accurate, and architecture/channel claims are current.

## Verified artifact sources

An `artifact` source must include verification material:

```toml
[sources.verification]
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
signer = "Expected Publisher Identity"
content_type = "application/zip"
max_bytes = 104857600
kind = "native-installer"
format = "msi"
install_arguments = []
```

The digest is exactly 64 hexadecimal SHA-256 characters. Signer, content type,
and byte limit add constraints; they are not shell commands. A valid manifest
does not by itself make an artifact executable: update/download verification,
safe extraction/installer typing, effective policy, and plan consent still
apply.

`format` is a closed enum: `zip`, `tar`, `tar.gz`, `msi`, `msix`, `exe`, `pkg`,
`dmg`, `deb`, `rpm`, or `appimage`. It must agree with `kind` and the source
platform. Only EXE recipes can declare flags, and each flag must be one of the
documented silent-mode values. DMG recipes additionally declare one safe
relative `.pkg` `payload_path`; no other format accepts an inner path. Native
Windows and macOS formats require `signer`. DEB/RPM may rely on the catalog
digest when no package-level signer can be established, subject to policy.

## Generation and review

```console
cargo xtask generate-catalog
cargo xtask test-catalog
cargo xtask build-site
python3 scripts/check_clean_tree.py catalog/generated website/public
```

Generation is deterministic. Catalog version/expiry belong to the generated,
signed snapshot rather than a package manifest. Signing happens only after
schema, identity, evidence, relationship, and generated-site checks pass.
