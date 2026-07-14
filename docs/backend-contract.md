# Backend adapter contract

An adapter translates a typed Siorb step into one native tool invocation. It is
not a resolver and does not receive arbitrary commands from catalog manifests.

## Capability model

Each detected adapter reports its implementation identity, resolved executable,
detected version, supported version range, and independent capability states
for search, installed-state query, plan install/remove/upgrade, execute each
operation, verify, and repair. A capability can be available, unavailable with a
stable reason, or conditional on interaction/scope/source.

Detection and query operations are read-only. Live smoke tests that could
refresh an index, accept agreements, install, remove, or upgrade require an
explicit disposable-test opt-in.

## Planning

An adapter accepts canonical native identity, validated source/channel/version,
scope, architecture, agreement state, and effective policy. It returns:

- executable identity and a separate argument vector;
- expected network endpoints/downloads when knowable;
- privilege and agreement requirements;
- verification strategy;
- conflicts/destructive-change signals;
- rollback or honest best-effort recovery guidance;
- redaction metadata for sensitive arguments.

Plans never contain a shell program. Backend IDs beginning with `-`, embedded
NUL/control characters, invalid encodings, and values outside the backend's ID
grammar are rejected before process creation. Use a backend's end-of-options
separator where supported, but never rely on it as the only validation.

## Execution

The executor resolves no package choices. It verifies that current executable,
catalog/policy/platform fingerprints, relevant state, and adapter capability
still match the plan; then spawns the recorded executable directly. Standard
output/error capture is bounded, timeouts are operation-specific, cancellation
updates the journal, and exit status is preserved.

Adapters classify at least not-found, source unavailable, permission denied,
network error, agreement required, conflict, unsupported version/capability,
verification failure, and unclassified backend failure. Parsers are
conservative: unexpected output does not become a false success.

## Non-interactive behavior

`--non-interactive` means no prompt may be awaited. The adapter must supply the
backend's documented non-interactive mode and preflight agreements/privilege, or
report that execution is impossible. `--yes` is operation consent; it is not an
agreement acceptance or permission to bypass policy. `--accept-agreements` is a
separate recorded choice.

## Contract tests

Every adapter needs fake-executable tests that assert exact arguments,
environment allowlist, working directory, exit/error mapping, output bounds,
control-character handling, timeout/cancellation, version detection, and every
advertised capability. Fixtures cover localized/changed output and malformed
machine data. Contract tests must demonstrate that catalog-controlled strings
cannot insert an option or second command.

Where hosted runners safely expose a native tool, CI may add read-only smoke
tests. Such a smoke test supplements rather than replaces fake-executable tests.

## Direct artifacts

The artifact adapter is stricter than a package-manager adapter: it downloads to
an isolated staging area, enforces redirect/scheme/domain/length limits,
verifies digest/signature and expected type before extraction, applies archive
entry/count/expanded-size rules, and permits only typed installer modes. There
is no manifest-provided pre/post-install shell hook.

The closed format set is Windows MSI/MSIX/EXE/ZIP, macOS PKG/DMG/ZIP, and Linux
DEB/RPM/AppImage/tar. MSI, PKG, DEB, and RPM use fixed system executables; MSIX
uses a fixed non-interactive Appx invocation; EXE accepts only a small enumerated
silent-flag set. A DMG is mounted read-only at an isolated mount point and may
name one safe relative PKG payload; the image is detached on every outcome.
Windows Authenticode and macOS package/code-signing identities must exactly
match catalog metadata. RPM key checks are enforced when a key id is declared;
DEB otherwise relies on the digest inside the signed Siorb catalog. AppImage is
never run as an installer: after ELF/AppImage header and digest verification it
is copied atomically into Siorb-owned state with private executable permissions.
