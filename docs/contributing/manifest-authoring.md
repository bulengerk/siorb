# Manifest authoring guide

Start from an existing manifest with the same backend and read
[the format reference](../catalog-format.md). One logical manifest represents an
upstream product; platform sources belong in `[[sources]]` rather than separate
logical packages unless upstream identities differ materially.

Use the upstream project's canonical name for `id`, then add only common,
unambiguous aliases. Put discoverability-only words in `search_terms`. Verify
every native ID from the backend's authoritative index and connect it to the
upstream homepage/publisher. Record the evidence URL and today's UTC review date
only after checking it.

Prefer trusted native or sandboxed sources. An artifact is a last-resort typed
source and must pin verification material; installation instructions containing
a shell pipeline are evidence for a human reviewer, never manifest content.

Before submitting:

```console
cargo xtask generate-catalog
cargo xtask test-catalog
cargo xtask build-site
git diff --check
python3 scripts/check_clean_tree.py catalog/generated website/public
```

The final command should pass after generated changes have been committed. Check
the rendered package page, search aliases, platform/source table, evidence, and
trust label. State which backend/index and architecture you actually verified.
