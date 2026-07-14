# Command reference

The canonical automation interface uses an explicit subcommand. `siorb firefox`
is convenience shorthand for `siorb install firefox`; it rejects names that are
ambiguous with commands or malformed input.

Run `siorb --help` and `siorb <command> --help` for the exact surface implemented
by the checked-out pre-1.0 build. The maintained command contract is grouped
below.

## Package discovery and planning

| Command | Purpose | Mutates host |
|---|---|---:|
| `search <query>` | fuzzy local discovery; never authorizes install | No |
| `info <package>` | exact logical metadata and sources | No |
| `why <package>` | selected/rejected candidate reason tree | No |
| `source list <package>` | compatible and rejected sources | No |
| `backend list` | detected adapter capabilities | No |
| `backend inspect <backend>` | version/capability diagnostics | No |
| `doctor` | normalized host facts and remediation | No |
| `plan <operation> [arguments...]` | immutable execution plan | No |

## Package and state operations

| Command | Purpose |
|---|---|
| `install <package...>` | install exact logical packages after plan/consent |
| `remove <package...>` | remove receipt/native identities permitted by policy |
| `upgrade [package...]` | plan upgrades, respecting pins/holds |
| `list` | observed and receipt-managed package state |
| `adopt [package...]` | create receipts after exact native identity confirmation |
| `reconcile` | compare intent, receipts, and backend state; never silently remove unknown software |
| `repair [package...]` | run advertised safe verification/repair capabilities |
| `pin <package> [version]`, `unpin <package>` | constrain Siorb resolution; backend enforcement limits remain visible |
| `hold <package>`, `unhold <package>` | prevent Siorb-planned change until released |
| `audit` | evaluate state/catalog/policy integrity without mutation |
| `verify [package...]` | re-check observed package/receipt verification |

Every modifying command plans first and revalidates immediately before a step.
A backend may partially succeed; exit 50 and the transaction journal distinguish
changed state from unstarted steps.

## Bundles and migration

```text
bundle validate <file>
bundle plan <file> [--profile <name>]
bundle apply <file> [--profile <name>]
bundle diff <file>
bundle lock <file> --output <lock-file> [--profile <name>]
migrate export --output <file>
migrate apply <file>
```

Portable intent is not a cross-platform native lock. See
[the bundle reference](../bundle-format.md) and [migration guide](../migration.md).

## Catalog and policy

```text
catalog status
catalog update
catalog verify [path]
catalog use <path-or-url>
policy validate <path>
policy explain <package>
```

Transport does not establish catalog authenticity. Local, file, cache, and HTTPS
sources all pass the same trusted-update checks. Policy explanation exposes
stable deny/require reason codes and layer identity.

## Maintenance

`self update` selects the newest compatible binary only from verified release
metadata, verifies the archive, safely extracts the executable, and replaces it
atomically (or immediately after process exit on Windows). Configure
`SIORB_RELEASE_MIRROR`; `--dry-run` verifies metadata without downloading the
archive, and real replacement requires confirmation or `--yes`. Any policy layer
can disable it with `allow_self_update = false`.
`completion <shell>` emits completion for PowerShell, Bash, Zsh, Fish, or another
shell advertised by the current build. `version` prints version/build identity.

## Global flags

| Flag | Meaning |
|---|---|
| `--dry-run` | fully resolve/plan/revalidate inputs but execute no mutation |
| `--json` | versioned machine output on stdout; diagnostics on stderr |
| `--non-interactive` | never wait for input; fail if consent/agreement/privilege cannot be preflighted |
| `--yes` | approve the shown operation; does not accept agreements or override policy |
| `--accept-agreements` | separately record backend agreement acceptance |
| `--via <backend>` | constrain backend, subject to policy/capability |
| `--source <source-id>` | constrain exact catalog source |
| `--scope <user|system|auto>` | requested installation scope |
| `--channel <stable|beta|nightly|custom>` | requested channel when catalog/policy support it |
| `--version <constraint>` | requested version constraint |
| `--arch <architecture>` | target architecture constraint; not an emulation bypass |
| `--offline` | prohibit network attempts; payload/index availability remains separate |
| `--explain` | include selection and rejection reasoning |
| `--catalog <path-or-url>` | select catalog transport/source |
| `--policy <path>` | add a local policy layer |
| `--color <auto|always|never>` | terminal color behavior |
| `--verbose`, `--quiet` | diagnostic detail; neither changes JSON semantics or policy |

Incompatible flag combinations fail before mutation. Exit codes and public
envelopes are documented in [JSON and exit codes](json-and-exit-codes.md).
