# ADR-0002: Enforce process and domain boundaries with a Rust workspace

- Status: Accepted
- Date: 2026-07-13
- Decision owners: Siorb maintainers

## Context

Resolver logic must be testable without a terminal or real package manager;
backend execution must not gain authority to reinterpret package intent. The
application needs a memory-safe, portable, mostly self-contained executable.

## Decision

Use Rust 2024 with MSRV 1.85 and explicit workspace crates for CLI, core,
platform, catalog, policy, resolver, planner, backends, executor, state, bundle,
update, and repository automation. Domain crates exchange typed values. Only
the executor spawns processes; only the CLI renders user-facing output. Unsafe
Rust is forbidden by workspace lint unless a future ADR defines a narrow audited
exception.

## Consequences

Pure logic can use fixtures/property tests and platform probes can be injected.
Crate boundaries add dependency and type plumbing, but make accidental privilege
or presentation coupling reviewable. A single CLI binary remains the preferred
runtime artifact.

## Alternatives considered

- One monolithic crate: rejected because resolver, IO, and process authority are
  too easy to couple.
- Plugins loaded from arbitrary dynamic libraries: rejected for the initial
  design because they widen the execution and compatibility trust boundary.
- A mandatory privileged helper/daemon: rejected; native per-step elevation is
  preferred.

## Verification

Workspace dependency review, compile-time APIs, fake-executable adapter tests,
and `cargo xtask verify` enforce boundaries and lint policy.
