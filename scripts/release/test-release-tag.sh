#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/siorb-release-tag-test.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
export GNUPGHOME="$TMP/gnupg"
mkdir -m 0700 "$GNUPGHOME"

if ! gpg --batch --passphrase '' \
  --quick-generate-key 'Siorb Release Test <release-test@example.invalid>' \
  ed25519 sign 1d >"$TMP/gpg.log" 2>&1; then
  if [[ "${SIORB_REQUIRE_TAG_SIGNING_TEST:-0}" == 1 ]]; then
    cat "$TMP/gpg.log" >&2
    exit 1
  fi
  echo "release tag verification test skipped: isolated GPG key generation is unavailable"
  exit 0
fi
FINGERPRINT=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')

git init -q "$TMP/repository"
cd "$TMP/repository"
git config user.name 'Siorb Release Test'
git config user.email 'release-test@example.invalid'
git config user.signingkey "$FINGERPRINT"
git config gpg.program gpg
touch evidence
git add evidence
git commit -q -m initial
git branch -M main
git update-ref refs/remotes/origin/main HEAD

git tag -s v1.2.3 -m 'Siorb 1.2.3'
"$ROOT/scripts/release/verify-release-tag.sh" v1.2.3 origin/main

git tag v1.2.4
if "$ROOT/scripts/release/verify-release-tag.sh" v1.2.4 origin/main >/dev/null 2>&1; then
  echo "lightweight release tag unexpectedly passed verification" >&2
  exit 1
fi

git switch -q -c unrelated
touch unrelated
git add unrelated
git commit -q -m unrelated
git tag -s v1.2.5 -m 'Siorb 1.2.5'
if "$ROOT/scripts/release/verify-release-tag.sh" v1.2.5 origin/main >/dev/null 2>&1; then
  echo "tag outside protected main unexpectedly passed verification" >&2
  exit 1
fi

echo "release tag verification tests passed"
