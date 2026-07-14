# ADR-0003: Authenticate static catalogs with role-based trusted metadata

- Status: Accepted
- Date: 2026-07-13
- Decision owners: Siorb maintainers

## Context

TLS authenticates a connection, not a package mapping over time. Static mirrors
can be stale, partially updated, or compromised. Clients must resist rollback,
freeze, threshold-key compromise, and mix-and-match attacks while retaining a
usable bundled catalog.

## Decision

Follow The Update Framework principles with offline-capable root and delegated
targets/snapshot/timestamp roles, threshold signatures, explicit versions and
expiry, consistent snapshot filenames, and length/digest binding. Root updates
are sequential and authorized by both old and new trust. Every transport feeds
identical verification. Only a complete verified snapshot is atomically made
active.

Catalog and release signing are separate trust domains. Offline root keys are
never placed in CI. Expiry tolerance, if allowed for disconnected operation, is
bounded by policy and visible to the user.

## Consequences

A static host or mirror cannot create trusted mappings or roll clients back.
Key ceremonies and metadata expiry introduce operational work, and clients need
persistent monotonic version state. Availability can be reduced when metadata
expires; that is an explicit security tradeoff rather than a silent bypass.

## Alternatives considered

- HTTPS plus checksum file: rejected; both can be replaced by the same host.
- One long-lived signing key: rejected; it has no role separation or threshold
  recovery.
- Accept newest timestamp by wall clock only: rejected; versions and bindings
  are required for rollback/mix-and-match resistance.

## Verification

Adversarial update tests listed in `docs/security/trusted-updates.md`, local
mirror tests, and root-rotation fixtures are release gates.
