# ADR-0004: Make immutable plans the only path to mutation

- Status: Accepted
- Date: 2026-07-13
- Decision owners: Siorb maintainers

## Context

Package managers differ in scope, agreement, privilege, rollback, and output.
Consent to a logical name is insufficient if environment or policy changes
between resolution and execution.

## Decision

Every mutation first produces a serializable immutable plan with selected
source, exact executable/arguments, downloads, verification, scope, privilege,
agreements, conflicts, recovery guidance, and fingerprints of security-relevant
inputs. The executor accepts typed plan steps only and revalidates mutable facts
immediately before use. Invalidating drift aborts. Dry-run performs this full
path and stops before mutation.

Transactions journal step boundaries. Siorb reports partial success when a
native backend cannot provide atomic rollback.

## Consequences

Users and automation can inspect the actual intended operation, consent is
specific, and time-of-check/time-of-use drift is bounded. Planning may query
installed state and backend capabilities, so it costs more than simple name
lookup. A plan is intentionally not a reusable authorization after its
fingerprints become stale.

## Alternatives considered

- Direct adapter invocation from CLI: rejected because it bypasses centralized
  policy, consent, and audit behavior.
- Whole-process elevation: rejected as unnecessary authority for resolution and
  download verification.
- Claim automatic rollback: rejected because native backends often cannot
  guarantee it.

## Verification

Plan golden tests, invariant/property tests, drift tests, and executor APIs must
show that no modifying adapter operation runs without successful revalidation.
