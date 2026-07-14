#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <artifact>..." >&2
  exit 2
fi
command -v cosign >/dev/null || { echo "cosign is required" >&2; exit 1; }

for artifact in "$@"; do
  [[ -f "$artifact" && ! -L "$artifact" ]] || { echo "artifact must be a regular non-symlink file: $artifact" >&2; exit 2; }
  bundle="${artifact}.sigstore.json"
  if [[ -n "${SIORB_COSIGN_KEY:-}" ]]; then
    cosign sign-blob --yes --key "$SIORB_COSIGN_KEY" --bundle "$bundle" "$artifact"
  else
    # Keyless mode requires an OIDC identity supplied by the execution environment.
    cosign sign-blob --yes --bundle "$bundle" "$artifact"
  fi
done
