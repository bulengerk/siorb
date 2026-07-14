# Security policy

Siorb plans and delegates software installation. Treat a suspected resolver,
catalog, signature, artifact, archive, privilege, or argument-validation flaw
as security-sensitive even if no exploit has been demonstrated.

## Reporting a vulnerability

Use the repository's private **Security > Advisories > New draft security
advisory** flow:

<https://github.com/bulengerk/siorb/security/advisories/new>

Do not open a public issue for an unpatched vulnerability. Include affected
versions or commit, host/platform, prerequisites, a minimal reproduction, the
expected security invariant, observed impact, and whether package installation
or elevation occurred. Remove credentials, access tokens, usernames, machine
names, and private repository URLs from logs.

Maintainers should acknowledge a report within 7 calendar days. Triage assigns
severity and an owner, reproduces in an isolated environment, and coordinates a
fix and advisory. No response-time promise should be interpreted as an embargo
agreement; reporters may state a desired disclosure date in the advisory.

## Supported versions

Siorb is pre-1.0 and has no supported production release at this time. Security
fixes are made on `main`. This table must be updated when the first release is
published; release tags and GitHub artifacts, not this document alone, are the
source of available versions.

| Version | Security fixes |
|---|---|
| Unreleased `main` | Yes |
| Published releases | None yet |

## Security invariants

- Resolution and planning need no elevation. Only the individual execution step
  may request it.
- Catalog, policy, bundle, backend output, and local state are untrusted input.
- Catalog fields never become shell syntax; subprocesses receive an executable
  and separate validated arguments with bounded output and time.
- A direct artifact is unusable until its digest or required signature and
  expected type have been verified. Extraction rejects traversal, links that
  escape the destination, unsafe names, and configured size limits.
- Catalog metadata is accepted only through the same trusted-update verification
  path, independent of HTTPS, file, cache, or mirror transport.
- Deterministic checked-in catalog roots are compromised test fixtures and are
  rejected by production publication; protected fingerprints bind separately
  created production roots.
- Version, expiry, threshold, role, length, and digest checks fail closed. An
  older cached catalog is not silently substituted for a failed update.
- Backend output is treated as data, stripped or escaped for terminal control
  sequences, bounded in logs, and redacted before persistence.
- Siorb has no mandatory service, account, telemetry collector, or remote
  resolver. Diagnostic data stays local unless the user sends it.

The detailed analysis is in [the threat model](docs/threat-model.md) and the
[trusted-update runbook](docs/security/trusted-updates.md).

## Dependency and build-chain response

CI runs locked dependency policy, vulnerability review, CodeQL, and secret
scanning where the repository settings permit it. A compromised dependency or
build action is handled as an incident: stop publication, preserve workflow and
artifact evidence, revoke affected credentials, rotate catalog/release keys if
exposed, rebuild from a reviewed commit, compare materials, and publish an
advisory. GitHub Actions are pinned to full commits so an upstream tag move does
not change execution.

## Release and catalog key compromise

Do not delete evidence or overwrite releases. Disable the protected publication
environment, revoke or remove the affected online key, and follow
[incident response](docs/security/incident-response.md). Catalog root rotation
requires the thresholds and old/new-root verification described in
[key rotation](docs/security/key-rotation.md). A release signing key and a
catalog role key are separate trust domains and should not share material.

## Local logs and cleanup

Logs and state use platform-standard application data directories and should
contain correlation IDs rather than user identity. Before sharing diagnostics,
inspect and redact them. Use the CLI's documented diagnostic cleanup operation
only when available in the current command reference; otherwise remove the
Siorb log directory manually after preserving receipts needed for recovery.
