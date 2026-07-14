# ADR-0005: Generate the catalog site from validated manifests

- Status: Accepted
- Date: 2026-07-13
- Decision owners: Siorb maintainers

## Context

Users need browsable catalog evidence, but separately maintained website data
would drift and a dynamic backend would violate offline/forkability goals.

## Decision

Generate deterministic static pages, search data, metadata, and sitemap from the
same validated catalog manifests consumed by the CLI. Host the output on GitHub
Pages or any static host. Search runs client-side. Generated files identify their
generator and CI fails if regeneration changes the tree.

The site is informational: copying a command never bypasses CLI exact-match,
policy, catalog signature, or plan checks.

## Consequences

Package facts have one source and forks can publish independently without a
service. Large catalogs increase generated output and browser index size, so
generation and search performance require measurement. Pages previews must not
receive release/catalog signing secrets.

## Alternatives considered

- Hand-maintained package pages: rejected because drift is inevitable.
- Search API/database: rejected because it creates a mandatory hosted service.
- Building the site from unvalidated pull-request data: rejected because
  malformed/unsafe content could be published or rendered inconsistently.

## Verification

`cargo xtask test-catalog`, `cargo xtask build-site`, a clean-tree diff, link and
accessibility checks, and the Pages workflow form the gate.
