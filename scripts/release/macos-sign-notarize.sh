#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 sign-binary <path> | sign-pkg <input.pkg> <output.pkg> | notarize <artifact> | staple <artifact>" >&2
  exit 2
}

[[ $# -ge 2 ]] || usage
ACTION=$1
shift

require_identity() {
  : "${SIORB_APPLE_APPLICATION_IDENTITY:?SIORB_APPLE_APPLICATION_IDENTITY is required}"
}

case "$ACTION" in
  sign-binary)
    [[ $# -eq 1 && -f "$1" && ! -L "$1" ]] || usage
    require_identity
    codesign --force --options runtime --timestamp --sign "$SIORB_APPLE_APPLICATION_IDENTITY" "$1"
    codesign --verify --strict --verbose=2 "$1"
    ;;
  sign-pkg)
    [[ $# -eq 2 && -f "$1" && ! -L "$1" ]] || usage
    : "${SIORB_APPLE_INSTALLER_IDENTITY:?SIORB_APPLE_INSTALLER_IDENTITY is required}"
    productsign --sign "$SIORB_APPLE_INSTALLER_IDENTITY" --timestamp "$1" "$2"
    pkgutil --check-signature "$2"
    ;;
  notarize)
    [[ $# -eq 1 && -f "$1" && ! -L "$1" ]] || usage
    : "${SIORB_APPLE_ID:?SIORB_APPLE_ID is required}"
    : "${SIORB_APPLE_TEAM_ID:?SIORB_APPLE_TEAM_ID is required}"
    : "${SIORB_APPLE_APP_PASSWORD:?SIORB_APPLE_APP_PASSWORD is required}"
    xcrun notarytool submit "$1" --wait \
      --apple-id "$SIORB_APPLE_ID" \
      --team-id "$SIORB_APPLE_TEAM_ID" \
      --password "$SIORB_APPLE_APP_PASSWORD"
    ;;
  staple)
    [[ $# -eq 1 && -f "$1" && ! -L "$1" ]] || usage
    xcrun stapler staple "$1"
    xcrun stapler validate "$1"
    ;;
  *) usage ;;
esac
