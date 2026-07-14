# Verify a release

There is no production release yet. When one is published, perform verification
in a new directory before executing or installing anything. Replace `VERSION`,
`TARGET`, `OWNER/REPOSITORY`, and filenames with values present on the same
immutable GitHub release. `OWNER/REPOSITORY` must name the repository that
published the release; do not substitute an unrelated upstream repository when
verifying a fork.

## 0. Verify the source tag when auditing source

Import a maintainer public key obtained through a reviewed independent channel,
fetch the annotated tag, and run `git verify-tag vVERSION`. Confirm that its
peeled commit is reachable from the protected `main` history and matches the
commit named by artifact provenance. Release CI performs the same signature and
ancestry gate with repository-configured public keys; a GitHub tag name alone is
not sufficient authorization.

## 1. Verify the signed checksum manifest

Download `SHA256SUMS` and `SHA256SUMS.sigstore.json`. With a reviewed current
Cosign installation:

```console
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity 'https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/vVERSION' \
  SHA256SUMS
```

The identity must name this repository's `release.yml` at the expected tag. Do
not loosen it to any GitHub workflow or trust a checksum file before this step.

## 2. Verify downloaded subjects

On Linux/macOS:

```console
sha256sum --ignore-missing --check SHA256SUMS
```

macOS may use `shasum -a 256` and compare the exact lowercase digest when GNU
`sha256sum` is unavailable. On Windows PowerShell:

```powershell
(Get-FileHash .\siorb-VERSION-TARGET.zip -Algorithm SHA256).Hash.ToLowerInvariant()
Select-String -Path .\SHA256SUMS -Pattern 'siorb-VERSION-TARGET.zip'
```

Require the filename and digest to match exactly. A partial check verifies only
the files actually downloaded.

## 3. Verify provenance

Download `ARTIFACTS.json` and the `.provenance.json` file named for the subject.
The signed `SHA256SUMS` binds both files and the artifact manifest binds every
listed path, length, and digest. Then verify the repository-hosted attestation
with GitHub CLI support:

```console
gh attestation verify siorb-VERSION-TARGET.tar.gz --repo OWNER/REPOSITORY
```

Confirm subject digest, workflow repository/ref, commit, and build environment.
Provenance describes how an artifact was built; it does not replace platform
signing, catalog trusted metadata, or your policy decision.

## 4. Verify platform trust signals

Windows:

```powershell
Get-AuthenticodeSignature .\siorb.exe | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
Get-AuthenticodeSignature .\siorb-VERSION-TARGET.msi | Format-List Status,StatusMessage,SignerCertificate,TimeStamperCertificate
```

Require `Status` to be `Valid` and inspect the expected publisher and timestamp.

macOS:

```console
codesign --verify --strict --verbose=2 ./siorb
codesign -dv --verbose=4 ./siorb
pkgutil --check-signature ./siorb-VERSION-TARGET.pkg
spctl --assess --type install --verbose=4 ./siorb-VERSION-TARGET.pkg
xcrun stapler validate ./siorb-VERSION-TARGET.pkg
```

Linux DEB/RPM files are repository-independent release assets. Their release
authenticity is the signed checksum/provenance above unless a future downstream
repository adds its own package signature. Do not infer a native repository
signature from the file extension.

## 5. Inspect catalog and SBOM

Verify the catalog ZIP against its bundled trusted role metadata using
`siorb catalog verify <directory>` after extraction to a new directory. Transport
checksums are insufficient for catalog authenticity. Inspect the SPDX JSON SBOM
and match its release version/materials before approving use in a restricted
environment.
