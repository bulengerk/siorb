#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <temporary-keychain-path>" >&2
  exit 2
fi
: "${SIORB_APPLE_CERTIFICATE_P12_BASE64:?SIORB_APPLE_CERTIFICATE_P12_BASE64 is required}"
: "${SIORB_APPLE_CERTIFICATE_PASSWORD:?SIORB_APPLE_CERTIFICATE_PASSWORD is required}"
: "${SIORB_APPLE_KEYCHAIN_PASSWORD:?SIORB_APPLE_KEYCHAIN_PASSWORD is required}"

KEYCHAIN=$1
P12=$(mktemp "${TMPDIR:-/tmp}/siorb-certificate.XXXXXXXX.p12")
trap 'rm -f -- "$P12"' EXIT
umask 077
printf '%s' "$SIORB_APPLE_CERTIFICATE_P12_BASE64" | openssl base64 -d -A >"$P12"
security create-keychain -p "$SIORB_APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$SIORB_APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$P12" -k "$KEYCHAIN" -P "$SIORB_APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$SIORB_APPLE_KEYCHAIN_PASSWORD" "$KEYCHAIN"
security list-keychains -d user -s "$KEYCHAIN"
