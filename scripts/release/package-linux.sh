#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <binary> <version> <x86_64|arm64> <deb|rpm|all> <output-dir>" >&2
  exit 2
}

[[ $# -eq 5 ]] || usage
BINARY=$1
VERSION=$2
ARCH=$3
FORMAT=$4
OUT=$5

[[ -f "$BINARY" && ! -L "$BINARY" ]] || { echo "binary must be a regular non-symlink file" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "package version must be stable MAJOR.MINOR.PATCH" >&2; exit 2; }
[[ "$ARCH" == "x86_64" || "$ARCH" == "arm64" ]] || usage
[[ "$FORMAT" == "deb" || "$FORMAT" == "rpm" || "$FORMAT" == "all" ]] || usage

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/siorb-package.XXXXXXXX")
trap 'rm -rf -- "$TMP"' EXIT

build_deb() {
  command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required for DEB packaging" >&2; exit 1; }
  local deb_arch
  case "$ARCH" in
    x86_64) deb_arch=amd64 ;;
    arm64) deb_arch=arm64 ;;
  esac
  local tree="$TMP/deb"
  install -D -m 0755 "$BINARY" "$tree/usr/bin/siorb"
  install -D -m 0644 "$ROOT/LICENSE" "$tree/usr/share/doc/siorb/copyright"
  install -D -m 0644 "$ROOT/packaging/linux/debian/control.in" "$tree/DEBIAN/control"
  sed -i "s/@VERSION@/$VERSION/g; s/@ARCH@/$deb_arch/g" "$tree/DEBIAN/control"
  find "$tree" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
  dpkg-deb --root-owner-group --build "$tree" "$OUT/siorb_${VERSION}_${deb_arch}.deb"
}

build_rpm() {
  command -v rpmbuild >/dev/null || { echo "rpmbuild is required for RPM packaging" >&2; exit 1; }
  local rpm_arch
  case "$ARCH" in
    x86_64) rpm_arch=x86_64 ;;
    arm64) rpm_arch=aarch64 ;;
  esac
  local top="$TMP/rpmbuild"
  mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
  install -m 0755 "$BINARY" "$top/SOURCES/siorb"
  install -m 0644 "$ROOT/LICENSE" "$top/SOURCES/LICENSE"
  install -m 0644 "$ROOT/packaging/linux/rpm/siorb.spec" "$top/SPECS/siorb.spec"
  rpmbuild -bb \
    --target "$rpm_arch" \
    --define "_topdir $top" \
    --define "siorb_version $VERSION" \
    "$top/SPECS/siorb.spec"
  find "$top/RPMS" -type f -name '*.rpm' -exec cp -- {} "$OUT/" \;
}

case "$FORMAT" in
  deb) build_deb ;;
  rpm) build_rpm ;;
  all) build_deb; build_rpm ;;
esac
