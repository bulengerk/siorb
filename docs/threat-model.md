# Threat model

## Scope and security objective

Siorb converts local intent into software installation. Its security objective
is to prevent an untrusted input, compromised mirror, ambiguous name, or backend
response from causing a different operation than the reviewed plan, and to
leave enough evidence to recover when a native backend only partially succeeds.

The model covers the CLI, bundled and updated catalogs, policy and bundle files,
resolver/planner, native backend adapters, direct artifacts, local state,
release artifacts, static website generation, and GitHub automation. It does
not make an upstream operating-system repository trustworthy; Siorb exposes
which trust domain is delegated to.

## Assets

- integrity of the selected logical and native package identity;
- integrity/freshness of catalog and release metadata;
- integrity of the execution plan, receipts, locks, and policy;
- confidentiality of credentials handled by native tools and CI;
- least-privilege execution and host availability;
- auditability of partial changes and provenance of release artifacts.

## Adversaries and boundaries

Adversaries may submit a malicious catalog change, control a static mirror or
DNS path, publish a typosquatted package, tamper with a download, influence
environment/path lookup, create hostile local files, emit crafted backend
output, or compromise a dependency/build action. A local administrator can
ultimately replace the binary or trust root and is outside the protection of an
unprivileged process; Siorb still avoids turning writable lower-trust files into
implicit elevated commands.

## Threats and controls

| Threat | Preventive controls | Detection/recovery |
|---|---|---|
| Malicious catalog contribution | schema constraints, exact IDs, evidence, ownership review, threshold signing | generated diff, catalog CI, immutable signed metadata |
| Typosquatting/alias collision | normalized canonical IDs, confusable checks, reserved command set, alias uniqueness; fuzzy search never auto-installs | ambiguity reason codes and candidate explanation |
| Backend option/argument injection | no shell strings, reject NUL/control input, `--` where backend supports it, typed adapter arguments | fake-executable contract tests and redacted argv in plans |
| Executable path hijacking | capability detection resolves and records executable identity/path; revalidate before use | fingerprint drift abort and doctor output |
| Unsafe temporary files | OS secure temporary directories, exclusive creation, restrictive permissions, no predictable shared path | cleanup journal and startup reconciliation |
| Archive traversal/bomb | normalized relative paths, reject absolute/parent/link escapes, entry and expanded-size limits, safe extraction destination | fail before installer execution; remove staging tree |
| Tampered mirror/download | role thresholds, hashes, lengths, versions and expiry; artifact digest/signer requirements | retain active verified snapshot; verification reason code |
| Rollback/freeze/mix-and-match | monotonic metadata versions, timestamp/snapshot binding, expiry, consistent snapshot paths | update refused; policy decides expired offline behavior |
| Unsafe policy/state permissions | do not follow unexpected links; ownership/mode checks where meaningful; atomic writes | doctor warning, backup/corruption recovery, refuse unsafe elevated use |
| Privilege confusion | resolve/plan unprivileged; elevation per step; no persisted credential | plan exposes exact privileged reason and unfinished journal |
| Terminal escape injection | backend output treated as bytes/data, control escaping and bounded capture | structured diagnostic excerpt, never replay raw output blindly |
| Secrets in logs/crashes | field-level redaction, argument classification, no telemetry, correlation ID without user identity | contributor redaction review and local deletion guidance |
| Dependency/build compromise | lockfile, audit/deny/CodeQL/dependency review, SHA-pinned actions, protected release environment | SBOM, provenance, reproducible-build comparison where practical |

## Direct artifact constraints

Artifact support is not a general script runner. A manifest may identify an
authenticated URL, expected digest/signer, content type, safe extraction mode,
and a closed set of typed installer flags. Redirect count, schemes, hosts,
download bytes, entry count, and expanded bytes are bounded. Verification
happens before extraction or execution. Platform signer checks supplement, not
replace, catalog-declared digest/provenance policy.

## Catalog update attacks

Tests must cover expired timestamp/snapshot/targets metadata, insufficient
thresholds, unauthorized root changes, version rollback, frozen timestamp,
cross-snapshot target substitution, hash/length mismatch, truncation, mirror
inconsistency, and interruption between prepare and commit. Transport adapters
produce bytes and source identity only; all pass through the identical verifier.

## Residual risks

- A trusted native repository may publish a malicious or newly compromised
  package under the correct ID. Catalog provenance and plan visibility reduce,
  but cannot eliminate, that risk.
- A package manager may mutate more state than its machine interface reports or
  may lack atomic rollback. Siorb records this as best-effort and journals
  partial completion.
- An already-compromised administrator account can replace local policy, trust
  roots, or the binary. Filesystem checks prevent accidental boundary crossing,
  not control of the machine owner.
- Offline expiry policy trades availability against freshness. Any grace window
  must be explicit, bounded, and visible in the plan; it is never silently
  enabled.

## Review triggers

Update this model when adding a backend capability, archive/installer type,
privilege helper, trust role or threshold, transport, self-update behavior,
public JSON field carrying sensitive data, or CI publication credential.
