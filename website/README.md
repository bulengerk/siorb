# Static catalog website

The website is generated directly from `catalog/packages/*.toml`; it has no separately maintained package database and no runtime backend.

```text
node website/build.mjs
node website/build.mjs --check
node website/validate.mjs
```

Serve `website/public/` with any static file server. The generator uses only Node.js built-ins, sorts every package and facet, and takes dates and catalog identity from `catalog/catalog.toml`, so identical inputs produce byte-identical output. JSON outputs, including `site.webmanifest`, carry an ignored `_generated` extension member with the regeneration command. The check mode compares every expected byte and rejects missing, stale, or unexpected generated files.

The committed output is repository-neutral: canonical URLs use the reserved
`https://example.invalid/siorb/` origin and repository links are rendered as
deployment-configured labels. A deployment supplies its own absolute HTTPS
values without editing the generator:

```text
SIORB_SITE_URL=https://OWNER.github.io/REPOSITORY/ \
SIORB_REPOSITORY_URL=https://github.com/OWNER/REPOSITORY \
node website/build.mjs
```

The Pages workflow sets both values from the repository that runs it. A fork
with a custom domain sets the public `SIORB_SITE_URL` repository variable.
