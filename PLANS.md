# Siorb implementation plan

This living plan follows dependency order. A checked item means implementation and automated evidence exist; release claims remain governed by `FINAL_CHECKLIST.md`.

## M0 - Repository and contracts

- [x] Establish the Rust workspace and explicit crate boundaries.
- [x] Define domain types, stable errors/exit codes, and JSON envelope v1.
- [x] Add repository instructions, ADRs, threat model, CI, and `cargo xtask` verification.
- [x] Enforce the append-only README work-session contract.

## M1 - Detection, catalog, and discovery

- [x] Normalize platform/distribution/architecture and backend capability detection.
- [x] Validate and bundle the signed static catalog.
- [x] Implement exact lookup, aliases, search, info, doctor, and catalog status.
- [x] Generate the offline static website from catalog sources.

## M2 - Resolution, plans, and primary adapters

- [x] Implement deterministic filtering/ranking with rejection reason codes.
- [x] Serialize immutable plans and validate consent/flag combinations.
- [x] Implement WinGet, Homebrew, APT, DNF, Yum, Pacman, and Flatpak adapters.
- [x] Cover dry-run install/remove/upgrade with fixtures and golden tests.

## M3 - Safe execution and state

- [x] Bound subprocess time/output and preserve typed failures.
- [x] Journal transactions and atomically store receipts, pins, and holds.
- [x] Implement mutation, adoption, reconciliation, repair, audit, and verification.
- [x] Add Snap, Zypper, APK, Scoop, Chocolatey, and MacPorts adapters.

## M4 - Bundles, policy, and artifacts

- [x] Validate portable intent, deterministic platform locks, export/apply/diff/refresh.
- [x] Enforce layered local policy with stable reason codes.
- [x] Verify artifacts and reject traversal, bombs, unsafe redirects, and option injection.
- [x] Add source/mirror selection and adversarial security tests.

## M5 - Trusted updates and production catalog

- [x] Verify root/targets/snapshot/timestamp metadata, rotation, thresholds, and expiry.
- [x] Implement rollback-resistant cache and transport-independent verification.
- [x] Ship at least 100 packages, 250 reviewed mappings, and top-package coverage evidence.
- [x] Complete deterministic catalog website and governance automation.

## M6 - Distribution and release readiness

- [x] Build cross-platform archives/installers/packages and signing hooks.
- [x] Generate checksums, SBOMs, provenance, symbols, and package-manager manifests.
- [x] Implement verified self-update and release workflows.
- [x] Record benchmark baselines, complete docs, and pass locally executable release gates.
- [ ] Collect protected multi-platform CI, production signing, and publication evidence (repository owner/external runners).
