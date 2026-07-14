# Trusted root fixtures

`root.json` is a human-readable TUF-compatible root used by the static metadata fixtures. `runtime-root.json` is the equivalent serialization expected by `siorb-update::Signed<RootMetadata>` and carries two independently verifiable Ed25519 signatures for its two-of-two root threshold.

Both roots are **development fixtures** built from public deterministic Ed25519 test vectors. The runtime fixture generator derives its signing material from conspicuously public labels so repositories remain reproducible; those keys are compromised by design. Neither root is suitable for a production catalog or release. Production roots must be created offline with independently controlled keys and distributed through an authenticated release process.
