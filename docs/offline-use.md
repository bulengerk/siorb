# Offline use and static mirrors

Siorb does not need a Siorb-operated service. Local search, package information,
resolution, explanation, bundle validation, and planning use the bundled or
cached verified catalog. Installing a package can still require an upstream
native repository or artifact; `--offline` does not make upstream payloads
appear locally.

## Fully disconnected planning

1. Install a Siorb release that contains a bundled verified catalog.
2. Select `--offline` for commands that must not attempt network access.
3. Run `siorb catalog status` and inspect catalog version/expiry.
4. Run discovery or a dry-run plan. A plan identifies any backend index or
   artifact that is not locally available.

An expired catalog is not silently treated as current. The effective policy
determines whether a bounded offline-tolerant window exists; status and plan
output identify that decision.

## Removable-media mirror

On a connected machine, copy the complete published catalog snapshot directory,
including trusted metadata and target files, without renaming individual files.
Also copy its release checksums or transport manifest for transfer diagnostics.
On the offline machine, use the local directory as the catalog source:

```console
siorb catalog verify /media/siorb/catalog
siorb catalog use /media/siorb/catalog
siorb --offline catalog update
```

The commands above are part of the stable command contract; consult
`siorb --help` for the exact options exposed by the checked-out build. Catalog
authenticity comes from trusted metadata, not from the USB device or checksum
file alone.

## HTTPS static mirror

Serve the release's catalog directory byte-for-byte from any static HTTPS host.
Preserve consistent-snapshot filenames, content types, and paths; do not add a
server-side API or rewrite metadata. Before announcing a mirror, verify the
directory before upload and test the deployed HTTPS base through normal update:

```console
siorb catalog verify ./catalog-snapshot
siorb catalog use https://mirror.example/catalog/
siorb catalog update
```

A mirror compromise should yield an update failure, not trusted metadata, as
long as threshold keys remain protected. Plain HTTP is never accepted.

The project's GitHub Pages deployment exposes the latest stable release's
verified snapshot at `/catalog/` in this same layout. The release workflow also
retains an immutable catalog ZIP for removable-media and third-party mirrors;
pre-releases are not promoted to the moving Pages path.

## Payload availability

A reproducible offline apply additionally needs every native repository index
and package payload or every verified direct artifact referenced by the lock.
Backend-specific caches remain owned by those backends. Siorb distinguishes:

- catalog metadata available locally;
- backend metadata/index available locally;
- payload bytes available locally;
- verification material available locally.

Do not describe a lock as cross-platform reproducible: each platform-specific
lock records that host's native identities and verification material.
