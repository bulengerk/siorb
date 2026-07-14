## Change

Describe the user-visible or internal behavior and why this boundary is the
smallest safe change.

## Security and compatibility

- Threat/trust boundary affected:
- JSON schema, exit code, catalog, policy, bundle, receipt, or plan compatibility:
- Privilege, network, native backend, or direct-artifact impact:
- Platforms verified and platforms not verified:

## Evidence

List commands and actual results. Host-mutating tests must name the disposable
environment; do not run them by default.

- [ ] `cargo fmt --check`
- [ ] strict workspace Clippy
- [ ] workspace tests
- [ ] `cargo xtask verify`
- [ ] relevant schema/catalog/docs/site checks
- [ ] generated output is committed and clean
- [ ] native packaging smoke is green when release inputs changed
- [ ] GitHub Actions remain pinned to full commit SHAs

## Documentation and provenance

- [ ] User-facing behavior and limitations are documented.
- [ ] Significant decisions have an ADR.
- [ ] Catalog mappings include exact-ID evidence and a review date.
- [ ] If Codex changed or meaningfully investigated the repository, exactly one
      new immutable entry was appended to the final README session log.

Do not include secrets, private source URLs, unredacted backend output, or
production signing material. Use a private Security Advisory for vulnerabilities.
