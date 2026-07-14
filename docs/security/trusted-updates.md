# Trusted catalog updates

Catalog authenticity is independent of transport. Bundled files, cache, local
directory, file URL, GitHub Pages/Release, or another HTTPS mirror all enter the
same verifier.

The trusted-update model uses root, targets, snapshot, and timestamp roles with
version and expiry enforcement, threshold signatures, consistent snapshot
names, and a bundled initial root/snapshot. The timestamp binds the expected
snapshot; snapshot binds target metadata; targets binds catalog content by
length and digest. Root updates are sequential and require old-root and new-root
threshold authorization.

## Update state machine

1. Load the active trusted root and persisted monotonic version state.
2. Apply every newer root version sequentially; reject skipped, rollback, or
   insufficiently authorized roots.
3. Fetch timestamp, reject expiry/rollback/bad threshold.
4. Fetch exactly the referenced snapshot, enforcing version, length, and hash.
5. Fetch referenced targets metadata and targets with the same binding checks.
6. Validate catalog schemas and internal identity before activation.
7. Commit the complete snapshot atomically and persist observed versions.

Failure before step 7 leaves the active snapshot unchanged. Offline use of an
expired timestamp requires an explicit bounded policy allowance and must remain
visible; a failed online update does not create such an allowance.

Self-update archives are ordinary signed targets with bound length/SHA-256 and
typed custom metadata: `kind` is `siorb-binary`, with version, normalized OS,
architecture, and archive format. There is no parallel unsigned release JSON.
The updater applies policy and platform matching only after trusted-target
verification.

The checked-in roots are reproducible development fixtures and are compromised
by design. Production publication replaces them through an offline ceremony;
protected automation checks their reviewed SHA-256 fingerprints, rejects
development/test key identifiers, requires separated role keys and a root
threshold of at least two, and never imports offline root private keys.

## Mirror requirements

Mirrors preserve bytes and consistent-snapshot paths. Redirects are bounded and
subject to scheme/domain policy. Mirrors do not receive signing keys. A mirror
health check is operational evidence only; it cannot vouch for authenticity.

## Required adversarial tests

- expired metadata and future/invalid times;
- threshold under-signing and unauthorized keys;
- root skipping, freeze, and version rollback;
- cross-snapshot/mix-and-match metadata;
- target length/digest mismatch and truncation;
- inconsistent mirrors and redirect policy violations;
- interruption before/during atomic activation;
- corrupt active/cache state recovery without trust bypass.
