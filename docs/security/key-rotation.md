# Catalog key rotation

Root keys are offline. Online timestamp, snapshot, and targets keys are separate
and least-privileged. Production ceremonies should use hardware-backed or
encrypted operator-controlled storage and record public key IDs, role,
threshold, participants, metadata versions, expiry, and verification output.
After review, update the protected runtime/standard-root SHA-256 variables to
the exact new public root files; never point them at the deterministic
development fixtures merely to make a workflow pass.

## Planned rotation

1. Prepare new keys offline and independently confirm public key fingerprints.
2. Add the new public key/role authorization in root version `N+1` while the old
   root is still valid.
3. Sign root `N+1` to the threshold required by root `N` and by `N+1`.
4. Verify sequential update from every supported bundled root; do not skip a
   root version.
5. Publish `N+1`, then publish fresh online metadata signed by authorized new
   keys with monotonically increasing versions.
6. Confirm multiple clean clients update through the complete chain.
7. After the overlap window, publish a later root removing retired keys and
   repeat dual-threshold verification.
8. Destroy or archive retired private material according to policy and retain
   public ceremony evidence.

## Compromise

Stop signing and publication, preserve audit evidence, identify affected roles
and earliest possible compromise, and notify maintainers. A compromised online
key can be revoked by new root metadata if root thresholds remain secure. If a
root threshold may be compromised, do not improvise an in-band reset: freeze
publication, ship a reviewed application update with a new trust bootstrap, and
publish an advisory explaining the manual recovery boundary.

Never lower thresholds, extend expired compromised metadata, reuse a release
code-signing key, or place an offline root key in CI to speed recovery.
