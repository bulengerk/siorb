# Incident response

## Contain

Disable the affected protected environment or catalog publication path; revoke
tokens and online keys known exposed; preserve workflow logs, audit events,
metadata, binaries, hashes, provenance, SBOM, and the exact commit. Do not
overwrite tags/releases or delete the only forensic copy.

## Assess

Determine affected trust domain (source, dependency, CI action, release key,
platform signing, catalog role, mirror, native backend mapping), earliest/latest
affected version, client exposure, and whether host mutation or privilege was
possible. Reproduce in isolation and compare release subjects against provenance
and an independent rebuild.

## Recover

Patch on a reviewed branch, rotate only the necessary credentials using the
documented ceremony, publish monotonically newer catalog metadata and/or a new
application version, and test a clean and an already-affected upgrade path.
Rollback resistance means catalog remediation uses a higher version, not old
metadata.

## Communicate and learn

Publish a GitHub Security Advisory with affected versions, indicators,
mitigation, fixed version, key changes, and verification instructions. Update
the threat model, tests, runbooks, and checklist. Record facts and evidence, not
speculation or secrets.
