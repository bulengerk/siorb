# Siorb documentation

Siorb resolves portable package intent locally, produces an auditable plan, and
delegates approved steps to native package managers or strictly verified
artifacts. The repository is pre-1.0; use the checked-out binary's `--help` and
release evidence rather than assuming a documented design is release-verified.

## Start here

- [Windows source setup](getting-started/windows.md)
- [macOS source setup](getting-started/macos.md)
- [Linux source setup](getting-started/linux.md)
- [Generated exact CLI help](generated/cli-reference.md) and
  [semantic command reference](reference/commands.md)
- [Troubleshooting](troubleshooting.md)
- [Known limitations](known-limitations.md)

## Concepts and formats

- [Architecture](architecture/index.md) and [data flow](architecture/data-flow.md)
- [Platform/support tiers](platform-support.md)
- [Backend adapter contract](backend-contract.md)
- [Catalog manifests](catalog-format.md)
- [Policy](policy-format.md)
- [Bundles and target locks](bundle-format.md)
- [Receipts and recovery](reference/state-and-receipts.md)
- [JSON and exit codes](reference/json-and-exit-codes.md)
- [Offline use and static mirrors](offline-use.md)
- [Migration](migration.md)

## Security and operations

- [Threat model](threat-model.md)
- [Trusted updates](security/trusted-updates.md)
- [Catalog key rotation](security/key-rotation.md)
- [Incident response](security/incident-response.md)
- [Release process](release-process.md)
- [Release verification](release-verification.md)
- [Catalog governance](contributing/catalog-governance.md)
- [Manifest authoring](contributing/manifest-authoring.md)
- [Architectural decisions](adr/README.md)

Public serialized contracts are under `schemas/`; catalog source schemas are
under `catalog/schemas/`. When prose and a current normative schema disagree,
validation follows the schema and the mismatch is a documentation defect.
