# Resolution and execution data flow

This document names the data crossing each boundary. The JSON schemas in
`schemas/` are normative for serialized public values; Rust types are normative
inside the process.

| Stage | Reads | Produces | Mutation allowed |
|---|---|---|---|
| Parse | arguments, environment allowlist | normalized request | No |
| Detect | stable OS APIs/files, executable metadata | `PlatformContext` | No |
| Load | trusted root, catalog, policy, state | verified inputs and fingerprints | Cache only after verification |
| Resolve | request, platform, catalog, policy, state | selected/rejected candidates and reason codes | No |
| Plan | resolution and backend capabilities | ordered immutable plan | No |
| Consent | plan and interaction mode | consent record or rejection | No |
| Revalidate | all plan fingerprints and relevant installed state | valid/invalid decision | No |
| Execute | validated step | bounded result | Native backend mutation |
| Record | journal and verification result | receipt or recovery record | Siorb state |

Machine output uses one JSON envelope so automation can distinguish command
failure from malformed process output. Diagnostics go to standard error in JSON
mode. Secrets, raw credentials, and unnecessary local identity are never fields
in the envelope.

Catalog updates follow a separate prepare/commit flow: download into an isolated
temporary location; enforce role, threshold, version, expiry, length and hash;
verify the complete snapshot; fsync as supported; atomically make it current;
retain the last verified snapshot according to local policy. A network failure
cannot partially replace the active catalog.
