# Troubleshooting

Start with a non-mutating diagnosis:

```console
siorb doctor --json
siorb catalog status
siorb backend list
```

With `--json`, standard output is machine data and diagnostics are written to
standard error. Preserve the correlation ID when reporting a problem; redact
local paths, private sources, tokens, proxy credentials, and backend arguments
before sharing output.

## Package is unresolved or ambiguous

Use `siorb search <query>`, then `siorb info <canonical-id>` and
`siorb why <canonical-id> --explain`. Installation requires an exact canonical
ID or unambiguous alias. Siorb intentionally does not auto-select the closest
fuzzy match. Check platform, architecture, channel, scope, backend availability,
catalog version, and policy rejection reason codes.

## Backend is installed but unavailable

Run `siorb backend inspect <backend>` and `siorb doctor`. The executable's mere
presence is insufficient: its version, machine-readable capability, source
configuration, architecture, and non-interactive support can all affect
availability. Avoid changing `PATH` only for an elevated step; the executable
identity recorded in the plan must still match at revalidation.

## Catalog update fails

Keep the current verified catalog. Run `siorb catalog status` and verify the
downloaded directory separately with `siorb catalog verify <path>`. Frequent
causes are expired timestamp metadata, rollback version, mismatched
snapshot/targets digest, insufficient signature threshold, truncation, or
mirror path rewriting. Do not bypass verification or replace the trusted root
to make an update succeed.

## Plan changed before execution

Siorb aborts if catalog/policy fingerprints, platform facts, backend identity,
or relevant installed state changed. Generate and review a new plan. This is a
security property, not a transient retry condition.

## Privilege denied

Inspect the plan for the exact step and scope requiring elevation. Prefer user
scope where the selected backend and policy permit it. In non-interactive mode,
configure a backend-supported non-interactive privilege path outside Siorb or
choose a non-privileged source; Siorb does not store a password or answer a
prompt on your behalf.

## Interrupted or partial operation

Do not delete the journal first. Run `siorb reconcile`, review its plan, then
use `siorb repair <package>` only when the backend advertises a safe repair
capability. Native backends may not offer atomic rollback. A receipt describes
what was verified, while an unfinished journal records steps that may have
changed state before failure.

## JSON consumer rejects output

Check `schema_version`, command, and process exit code. Ignore unknown fields in
a compatible schema version; do not infer success from exit code alone when a
result reports partial completion. If diagnostics appear in stdout under
`--json`, report it as a bug with a minimal reproduction.

## Report a defect

Use the bug template for ordinary defects. Use the private process in
[SECURITY.md](../SECURITY.md) for anything that could select or execute an
unreviewed operation, bypass verification/policy, cross privilege boundaries,
or expose secrets.
