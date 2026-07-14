#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/siorb-packaging-test.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
export SOURCE_DATE_EPOCH=1234567890

for output in "$TMP/first" "$TMP/second"; do
  mkdir -p "$output"
  python3 "$ROOT/scripts/release/package_archive.py" \
    --binary /bin/true --target x86_64-unknown-linux-gnu \
    --version 0.1.0 --output-dir "$output"
  python3 "$ROOT/scripts/release/package_archive.py" \
    --binary /bin/true --target x86_64-pc-windows-msvc \
    --version 0.1.0 --output-dir "$output"
  python3 "$ROOT/scripts/release/package_archive.py" \
    --binary /bin/true --target aarch64-pc-windows-msvc \
    --version 0.1.0 --output-dir "$output"
done

cmp "$TMP/first/siorb-0.1.0-x86_64-unknown-linux-gnu.tar.gz" \
  "$TMP/second/siorb-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
cmp "$TMP/first/siorb-0.1.0-x86_64-pc-windows-msvc.zip" \
  "$TMP/second/siorb-0.1.0-x86_64-pc-windows-msvc.zip"
cmp "$TMP/first/siorb-0.1.0-aarch64-pc-windows-msvc.zip" \
  "$TMP/second/siorb-0.1.0-aarch64-pc-windows-msvc.zip"

python3 "$ROOT/scripts/release/package_symbols.py" \
  --symbols /bin/true --version 0.1.0 \
  --target x86_64-unknown-linux-gnu --output-dir "$TMP/first"
python3 "$ROOT/scripts/release/checksums.py" \
  --directory "$TMP/first" --output "$TMP/first/SHA256SUMS"
python3 "$ROOT/scripts/release/verify_release.py" \
  --directory "$TMP/first" --checksums "$TMP/first/SHA256SUMS" --inspect-archives
python3 "$ROOT/scripts/release/test_release_helpers.py"
"$ROOT/scripts/release/test-release-tag.sh"

mkdir -p "$TMP/winget"
python3 "$ROOT/scripts/release/generate_winget.py" \
  --version 0.1.0 \
  --base-url https://github.com/bulengerk/siorb/releases/download/v0.1.0 \
  --x86-64 "$TMP/first/siorb-0.1.0-x86_64-pc-windows-msvc.zip" \
  --arm64 "$TMP/first/siorb-0.1.0-aarch64-pc-windows-msvc.zip" \
  --output-dir "$TMP/winget"
python3 -c 'import re, sys; values = re.findall(r"(?m)^  - Architecture: ([^\r\n]+)$", open(sys.argv[1], encoding="utf-8").read()); assert sorted(values) == ["arm64", "x64"], values' \
  "$TMP/winget/Siorb.Siorb.installer.yaml"
python3 "$ROOT/scripts/release/generate_homebrew.py" \
  --version 0.1.0 \
  --base-url https://github.com/bulengerk/siorb/releases/download/v0.1.0 \
  --aarch64 "$TMP/first/siorb-0.1.0-x86_64-unknown-linux-gnu.tar.gz" \
  --x86-64 "$TMP/first/siorb-0.1.0-x86_64-unknown-linux-gnu.tar.gz" \
  --output "$TMP/siorb.rb"
if grep -R -E '@[A-Z0-9_]+@' "$TMP/winget" "$TMP/siorb.rb"; then
  echo "generated downstream metadata contains an unexpanded marker" >&2
  exit 1
fi
python3 "$ROOT/scripts/release/archive_directory.py" \
  --directory "$TMP/winget" --output "$TMP/winget.zip"
python3 -m zipfile -t "$TMP/winget.zip"

python3 -c 'import sys, xml.etree.ElementTree as ET; ET.parse(sys.argv[1])' \
  "$ROOT/packaging/windows/siorb.wxs"
for variable in SiorbVersion SiorbBinary LicensePath; do
  if ! grep -F "\$(var.$variable)" "$ROOT/packaging/windows/siorb.wxs" >/dev/null; then
    echo "WiX source is missing the required preprocessor variable: $variable" >&2
    exit 1
  fi
done

if command -v dpkg-deb >/dev/null; then
  mkdir -p "$TMP/deb-first" "$TMP/deb-second"
  "$ROOT/scripts/release/package-linux.sh" /bin/true 0.1.0 x86_64 deb "$TMP/deb-first"
  "$ROOT/scripts/release/package-linux.sh" /bin/true 0.1.0 x86_64 deb "$TMP/deb-second"
  cmp "$TMP/deb-first/siorb_0.1.0_amd64.deb" "$TMP/deb-second/siorb_0.1.0_amd64.deb"
  dpkg-deb --info "$TMP/deb-first/siorb_0.1.0_amd64.deb" >/dev/null
fi

echo "release packaging smoke test passed"
