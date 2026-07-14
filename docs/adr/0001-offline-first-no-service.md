# ADR-0001: Resolve locally without an owner-operated service

- Status: Accepted
- Date: 2026-07-13
- Decision owners: Siorb maintainers

## Context

Package installation is needed during outages, migrations, recovery, and on
restricted networks. A central resolver would add availability, privacy,
account, and long-term ownership risks. Static distribution can be mirrored and
authenticated independently of its host.

## Decision

All catalog lookup, normalization, resolution, policy, plan generation, and
explanation happen in the local process using a bundled or cached verified
catalog. Updates are static files accepted only after trusted-metadata
verification. Siorb will not require accounts, a hosted database/API, remote
execution, telemetry, or an always-on daemon. Native package repositories and
artifact origins remain explicit upstream network dependencies.

## Consequences

Core discovery and planning work without Siorb infrastructure, forks can operate
independently, and users can substitute a local/static mirror. Catalog releases
must be compact, signed, cacheable, and shipped with the binary. Server-side
personalization and real-time resolution are unavailable; local catalog freshness
and update expiry must be exposed honestly.

## Alternatives considered

- Central resolution API: rejected because it becomes a mandatory owner service
  and makes an install decision opaque/offline-unavailable.
- Native managers only with no semantic catalog: rejected because portable
  logical intent cannot resolve consistently across platforms.
- Unsigned static JSON: rejected because transport compromise could alter the
  install mapping.

## Verification

Offline integration tests block network and exercise search/info/resolve/plan.
Update tests use interchangeable file/HTTP transports through one verifier.
Repository review rejects mandatory service dependencies.
