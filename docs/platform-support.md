# Platform and backend support

Siorb separates an architectural target from a verified support claim. A host
is supported by a release only when that release's checklist links automated
fixtures/contract tests and a build/install smoke result for the relevant row.
The repository is currently pre-1.0; no tagged production support statement has
been published.

## Support levels

- **Release-verified**: built and tested by the tagged release workflow, with
  backend contract evidence and an installer/archive smoke test.
- **CI-covered**: build and non-mutating tests run on the host family, but no
  production installer claim follows automatically.
- **Fixture-covered**: platform detection and adapter behavior are tested with
  fixtures/fake executables only.
- **Designed**: the normalized platform/backend model has a documented target,
  but release evidence is absent.

`siorb doctor --json` is authoritative for one machine. Backend availability is
a runtime fact; distribution is never inferred solely from an executable.

The detector also derives a typed `supported`, `unsupported`, or `undetermined`
compatibility result from the stable reason codes below. This classifies the
implemented detector/adapter contract only; release verification remains a
separate, stricter claim.

## Detector compatibility baselines

| Host | Versions classified as compatible | Outside the baseline |
|---|---|---|
| Windows | NT 10.0 build 17763 or newer, x86_64/ARM64 | older builds are `unsupported_os_version`; an unknown/new kernel family is `os_version_unverified` |
| macOS | major versions 13 through 26, x86_64/ARM64 | older is unsupported; newer or missing is unverified |
| Debian | major versions 12 and 13 | older is unsupported; newer or missing is unverified |
| Ubuntu | major versions 22 through 26 | older is unsupported; newer or missing is unverified |
| Fedora | major versions 41 through 43 | older is unsupported; newer or missing is unverified |
| RHEL family | major versions 9 and 10 | older is unsupported; newer or missing is unverified |
| Arch/Arch Linux ARM | rolling release identity | an unrecognized derivative is unverified or unsupported |
| openSUSE/SUSE | major versions 15 and 16 | older is unsupported; newer or missing is unverified |
| Alpine | versions 3.20 through 3.23 | older is unsupported; newer or missing is unverified |

Known derivatives inherit backend candidates, but remain
`distribution_version_unverified` unless their own lifecycle/version mapping is
encoded. Only x86_64 and ARM64 are in this compatibility matrix; an unknown
architecture is `architecture_unverified`, while x86/ARM are unsupported.
These bounds are deliberately finite so a future OS is not silently promoted
without a new fixture and review.

## Required host matrix

| Host family | Architectures in the product contract | Candidate backends | Release evidence required |
|---|---|---|---|
| Windows 10/11 and supported Server | x86_64; ARM64 where upstream mappings exist | WinGet, Scoop, Chocolatey, verified MSI/MSIX/EXE/ZIP | Windows runner tests, adapter contracts, signed/unsigned-local installer smoke as applicable |
| macOS | x86_64, Apple Silicon ARM64 | Homebrew formula/cask, MacPorts, verified PKG/DMG/ZIP | both architecture builds or documented universal artifact, adapter contracts, archive/package smoke |
| Debian/Ubuntu | x86_64, ARM64 | APT, Snap, Flatpak, verified DEB/AppImage/archive | detection fixtures for family/version, container adapter tests, DEB/archive smoke |
| Fedora/RHEL | x86_64, ARM64 | DNF/DNF5, Flatpak, verified RPM/AppImage/archive | family/version fixtures, container adapter tests, RPM/archive smoke |
| Arch Linux | x86_64; ARM64 where repositories support it | Pacman, Flatpak, verified AppImage/archive | fixtures and disposable integration test |
| openSUSE | x86_64, ARM64 | Zypper, Flatpak, verified RPM/AppImage/archive | fixtures and disposable integration test |
| Alpine | x86_64, ARM64 | APK, optional Flatpak, verified archive | musl detection/build evidence and disposable integration test |

Nix and additional native managers are extension candidates, not currently part
of the required adapter set.

## Detection contract

The normalized context records OS and version, Linux distribution ID/version
and ancestry, architecture and translation/emulation state, relevant libc,
available backend versions/capabilities, terminal mode, scope/elevation
capability without user identity, offline state, and selected catalog/policy.

Important fixtures include containers, compatibility layers, incomplete backend
installs, missing tools, unsupported versions, translated macOS processes,
Windows architecture differences, and Linux derivatives. Detection uses stable
OS APIs and files such as `/etc/os-release`; executable discovery adds backend
facts but does not define the distribution.

## Backend selection

The safe default priority is: explicit source, permitted policy preference,
trusted native system source, trusted sandboxed source, verified upstream
artifact, then unresolved. Siorb does not fall back to a community or unverified
download merely because a preferred mapping is missing.

Unsupported capability is typed data. For example, an adapter can support
installed-state query but not repair, or interactive install but not
non-interactive install. The planner rejects an operation requiring a missing
capability before consent.

An executable is reported as available only after a bounded `--version`-style
probe succeeds, yields a parseable version, and falls in the reviewed command
contract below. A missing executable is omitted. A present but unprobed, too
old, or future-major executable remains visible with `available: false`, its
capability allowlist empty, and its observed version retained when parseable.

| Adapter | Reviewed version interval | Advertised capabilities |
|---|---|---|
| WinGet | `>=1.6,<2` | query, install, remove, upgrade, repair, verify, non-interactive |
| Scoop | `>=0.4,<1` | query, install, remove, upgrade, repair, verify |
| Chocolatey | `>=2,<3` | query, install, remove, upgrade, repair, verify, non-interactive |
| Homebrew | `>=4,<5` | query, install, remove, upgrade, repair, verify |
| MacPorts | `>=2.8,<3` | query, install, remove, upgrade, repair, verify |
| APT | `>=2,<4` | query, install, remove, upgrade, repair, verify, non-interactive |
| DNF/DNF5 | `>=4,<6` | query, install, remove, upgrade, repair, verify, non-interactive |
| Pacman | `>=6,<8` | query, install, remove, upgrade, repair, verify, non-interactive |
| Flatpak | `>=1.12,<2` | query, install, remove, upgrade, verify, non-interactive |
| Snap | `>=2.58,<3` | query, install, remove, upgrade, repair, verify |
| Zypper | `>=1.14,<2` | query, install, remove, upgrade, repair, verify, non-interactive |
| APK | `>=2.14,<3` | query, install, remove, upgrade, repair, verify, non-interactive |

The intervals describe the argument/parser behavior exercised by Siorb tests,
not the upstream project's support lifecycle. Native backend search is not
advertised: `siorb search` is local catalog search. Interaction is advertised
only where the generated argument vector explicitly suppresses prompts or the
backend contract is intrinsically non-interactive.

Windows currently reports `external_elevation_unavailable`,
`elevation_available: false`, and user scope only. The executor deliberately
fails closed for external elevated Windows commands until a broker can validate
the executable, signer, DACL ownership, and reparse-point boundary. Planning and
user-scope operations remain available; the detector does not promise a system
scope the executor cannot execute.

## How to update this document

Golden platform outputs are regenerated conceptually from checked-in detector
inputs: OS release data, process/native architecture, terminal/elevation facts,
environment restrictions, fake executables, and bounded probe output. A
deserialize/reserialize round trip is not accepted as detector coverage.

When promoting a row, link its release-run evidence from `FINAL_CHECKLIST.md`,
state exact runner/image and backend versions, and record limitations. Do not
change a support level based only on successful compilation or a local manual
test.
