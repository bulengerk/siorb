# Catalog governance

Catalog changes can redirect an install to a different publisher or privilege
scope and therefore require security-focused review.

## Mapping acceptance

A mapping counts as reviewed only when it has a canonical logical identity,
exact backend ID, supported platform/architecture evidence, upstream publisher
match, trust/scope/channel classification, current evidence URL and review date,
verification strategy, fixtures, schema validation, and no alias/reserved-name
collision. Direct artifacts additionally need pinned/authenticated digest
material and bounded typed installer/extraction metadata.

Do not accept scraped popularity alone, an unverified community package as a
silent fallback, mutable download URLs without verification, arbitrary shell
instructions, or a mapping whose ownership cannot be related to the upstream
project.

## Review flow

1. Contributor edits only source manifests and supplies evidence.
2. Generation produces a deterministic catalog/site diff.
3. CI validates schemas, IDs, relationships, exact mappings, evidence freshness,
   safe URLs, and catalog totals; backend fixtures cover translation.
4. A reviewer independently checks exact native identity and publisher.
5. Security-sensitive artifacts, trust changes, alias additions, privilege
   changes, and key metadata receive an additional maintainer review.
6. Threshold signing happens after merge from the protected catalog environment;
   pull requests never receive signing keys.

Scheduled health checks report stale review dates, changed/missing evidence, and
mapping/index failures as artifacts and issues. They do not automatically
rewrite or sign manifests.

## Removal and incident handling

Deprecate aliases before removal where safe. A compromised mapping is denied in
new monotonically versioned metadata immediately; do not serve an older
snapshot as rollback. Preserve affected metadata/evidence, publish an advisory
when users may have installed it, and add a regression fixture.
