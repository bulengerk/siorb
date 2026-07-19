# Portable bundle and lock format v1

A bundle expresses portable intent. Each lock records one platform-specific
resolution. They are deliberately different: copying Linux native IDs into a
Windows lock would not be reproducible or meaningful.

## Intent file

The conventional filename is `siorb.toml`:

```toml
schema_version = "1.0"
name = "developer-workstation"
policy_references = ["builtin-secure-defaults"]

[feature_groups]
developer-tools = ["example-optional-tool"]

[profiles]
default = ["firefox", "@developer-tools"]

[metadata]
purpose = "developer workstation example"

[[packages]]
id = "firefox"
state = "present"
channel = "stable"
scope = "auto"
optional = false
features = ["core"]
platforms = ["windows", "macos", "linux"]
allow_backends = []
deny_backends = ["artifact"]
on_conflict = "error"

[[packages]]
id = "example-optional-tool"
state = "present"
version = ">=1,<2"
channel = "stable"
scope = "user"
optional = true
features = ["development"]
platforms = ["linux"]
allow_backends = ["apt", "dnf", "yum", "pacman"]
deny_backends = []
on_conflict = "error"
```

`name`, policy references, feature groups, and profiles are optional. Feature
groups are named lists of package IDs; profiles can include package IDs and
groups using `@group-name`. Every policy reference must match an active local
policy layer before resolution. `packages` is ordered input but lock output uses
deterministic canonical ordering. Each package contains:

| Field | Meaning |
|---|---|
| `id` | exact logical catalog identity |
| `state` | `present` or `absent` |
| `version` | optional version constraint, not a native package ID |
| `channel` | `stable`, `beta`, or `nightly` |
| `scope` | `user`, `system`, or `auto` |
| `optional` | failure may be reported without preventing required entries, subject to apply semantics |
| `features` | declarative feature labels carried into the platform lock |
| `platforms` | empty/all or explicit normalized platform selectors |
| `allow_backends`, `deny_backends` | per-intent constraints, still subordinate to policy |
| `on_conflict` | optional named conflict behavior; unsupported values must fail validation rather than becoming commands |

Platform selectors control applicability, not source selection. An absent entry
never authorizes removal when effective policy prevents uninstall. Conflicts,
dependencies, and package availability are resolved from the selected catalog;
the bundle cannot inject commands or backend arguments.

## Validation and planning

```console
siorb bundle validate siorb.toml
siorb bundle plan siorb.toml --profile default --dry-run --explain
siorb bundle diff siorb.toml
siorb bundle lock siorb.toml --profile default --output siorb.lock.json
siorb bundle refresh siorb.toml --profile default --lock siorb.lock.json
siorb bundle apply siorb.toml --profile default --lock siorb.lock.json
```

Validation reports source location and actionable parse/field errors. Planning
normalizes IDs, expands the selected profile and feature groups, evaluates
platform conditions and policy, resolves exact sources, checks installed state,
and emits one immutable plan. Apply revalidates that plan before any step.
Supplying `--lock` additionally requires an exact intent, profile, catalog,
policy, platform, observed-version, source, and verification-material match.

`schemas/v1/bundle.schema.json` describes the fully materialized serialized
representation. The TOML reader supplies defaults for omitted optional input
fields; the serialized form includes `name` (possibly null), `metadata`, policy
references, feature groups, profiles, and every package field explicitly.

## Resolved lock

The normative machine schema is
`schemas/v1/bundle-lock.schema.json`. It records `schema_version`, intent
fingerprint, catalog version/fingerprint, policy fingerprint, platform
fingerprint plus normalized OS/architecture, and deterministically ordered
locked packages. The selected profile and declared policy references are bound
into the lock. Each package binds logical/desired identity, exact source,
backend/native ID, optional version, scope/channel, and a fingerprint of its
resolution explanation.

The schema rejects unknown top-level data. A lock for another platform is
evidence, not authorization to use its native IDs. Resolve the same portable
intent separately to create another platform lock. `siorb bundle refresh`
produces a human-readable report covering catalog, policy, platform, package,
source, version, verification, and explanation changes before replacing the
selected lock (or writing `--output`).

## Migration and offline use

`siorb migrate export` creates portable intent from installed/adopted receipts;
it does not claim ownership of unrelated software. Applying on another host
resolves the intent for that host and creates a distinct lock. Offline
apply succeeds only if catalog, backend index/package payload or verified
artifact, and all verification material are already available.

Do not store tokens, private source credentials, absolute machine paths, or user
identity in intent or locks.
