# Known limitations

- No production Siorb release has been published at the time of this pre-1.0
  documentation. Source builds and CI definitions are not signed release
  artifacts.
- The checked-in trusted roots are deterministic, publicly compromised fixtures
  for update tests. A source build using them has development trust only;
  protected publication rejects them and requires separately created,
  fingerprint-pinned production roots.
- Support is release-evidence based. A catalog mapping or successful compile
  alone does not prove a backend/platform row is release-verified.
- Windows external-command elevation is not implemented. The detector reports
  user scope only and privileged Windows plans fail closed; UAC availability is
  not advertised as executor capability.
- Native package managers can mutate global state and often cannot provide
  atomic rollback. Siorb journals and reports partial completion instead of
  manufacturing rollback guarantees.
- A correct native package ID does not protect against compromise of the trusted
  native repository/publisher. Plans make that delegated trust visible.
- Offline catalog resolution does not imply that native indexes or package
  payloads are cached. Full offline apply depends on the selected backend/source.
- Version and hold semantics differ by backend. Siorb can constrain its own
  plans but cannot prevent changes performed directly outside Siorb.
- Direct artifacts are allowed only where catalog verification metadata,
  effective policy, safe extraction/installer typing, and platform support all
  agree. There is no arbitrary manifest lifecycle-script escape hatch.
- Byte-for-byte reproducibility of platform installers may be affected by code
  signing timestamps, Apple notarization tickets, native packaging tools, and
  toolchain paths. Each release records measured evidence rather than claiming
  reproducibility by design alone.
- Catalog evidence can become stale between scheduled checks. Runtime signature
  verification protects catalog bytes/versions, not the continued honesty of an
  upstream package under the same identity.
