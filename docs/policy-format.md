# Local policy format v1

Policy is local TOML evaluated before source ranking. It cannot add an unsafe
candidate or weaken a higher-precedence rule. Precedence, from strongest base to
most specific permitted choice, is: built-in secure defaults, machine policy,
organization local policy, user policy, then command-line choices only where
higher layers allow an override.

```toml
schema_version = "1.0"
id = "workstation-baseline"

allow_packages = []
deny_packages = ["unapproved-tool"]
allow_categories = ["browsers", "developer-tools", "security"]
deny_categories = []
allow_sources = []
deny_sources = []
allow_backends = ["apt", "flatpak"]
deny_backends = ["artifact"]
allow_channels = ["stable"]
deny_channels = ["beta", "nightly"]
allow_scopes = ["user", "system"]
deny_scopes = []
allow_licenses = ["Apache-2.0", "MIT", "MPL-2.0"]
deny_licenses = []
preferred_backends = ["apt", "flatpak"]

require_signatures = true
require_digests = true
trusted_publishers = []
minimum_provenance = "backend-repository"
forbid_artifacts = true
forbid_prerelease = true
require_confirmation = true
require_dry_run = false
network_domains = ["packages.example.org"]
prevent_downgrade = true
prevent_uninstall = false
freshness_days = 30
```

An empty `allow_*` list means that layer adds no allowlist restriction; it does
not mean deny everything. When a list is non-empty, candidates must match it.
Any matching `deny_*` rule rejects a candidate and wins over preferences and
command-line selection. `preferred_backends` is an ordered ranking preference,
not permission.

## Security controls

- `require_signatures` requires an accepted signature strategy for the selected
  source; a digest alone is insufficient.
- `require_digests` requires pinned or authenticated upstream digest material
  for direct artifacts. Native repository metadata remains governed by its
  backend trust model and any stronger signature rule.
- `trusted_publishers` restricts accepted signer/publisher identities. Empty
  means no additional publisher allowlist at this layer.
- `minimum_provenance` names the minimum catalog provenance classification.
- `forbid_artifacts` rejects every direct artifact regardless of its digest.
- `forbid_prerelease` rejects beta/nightly/custom pre-release selection.
- `require_confirmation` prohibits implicit consent; `--yes` cannot override it
  when the rule requires an interactive review.
- `require_dry_run` prevents mutation and is useful for audit-only hosts.
- `network_domains` is a non-empty allowlist for plan endpoints. Redirect hosts
  are evaluated too.
- `prevent_downgrade` and `prevent_uninstall` constrain operations after source
  resolution.
- `freshness_days` bounds catalog age. Offline tolerance never silently changes
  the signed metadata expiry check.

Unknown fields and invalid enum/identifier/domain values fail validation. Policy
files contain no commands, credentials, repository passwords, or environment
expansion. File origin, fingerprint, and applied reason codes appear in
explanation/plan output, but sensitive local path details need not appear in
shared diagnostics.

## Reasoning and validation

Every rule outcome uses a stable reason code, for example a package denial,
backend denial, artifact prohibition, freshness failure, or non-overridable
scope restriction. `siorb policy validate <path>` checks syntax/semantics without
installation, and `siorb policy explain <package>` shows the effective layered
decision. Consult the build's `--help` while the pre-1.0 CLI evolves.
