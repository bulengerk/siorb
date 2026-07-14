#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <siorb-binary> <MAJOR.MINOR.PATCH> <output.pkg>" >&2
  exit 2
fi

BINARY=$1
VERSION=$2
OUTPUT=$3
[[ -f "$BINARY" && ! -L "$BINARY" ]] || { echo "binary must be a regular non-symlink file" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be stable MAJOR.MINOR.PATCH" >&2; exit 2; }
command -v pkgbuild >/dev/null || { echo "pkgbuild is required (run this on macOS)" >&2; exit 1; }

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/siorb-pkg.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
PAYLOAD="$TMP/payload"
mkdir -p "$PAYLOAD/usr/local/bin" "$PAYLOAD/usr/local/share/doc/siorb"
install -m 0755 "$BINARY" "$PAYLOAD/usr/local/bin/siorb"
install -m 0644 "$ROOT/LICENSE" "$PAYLOAD/usr/local/share/doc/siorb/LICENSE"
mkdir -p "$(dirname "$OUTPUT")"

pkgbuild \
  --root "$PAYLOAD" \
  --identifier dev.siorb.cli \
  --version "$VERSION" \
  --install-location / \
  "$OUTPUT"

pkgutil --check-signature "$OUTPUT" || true
pkgutil --payload-files "$OUTPUT" | LC_ALL=C sort
