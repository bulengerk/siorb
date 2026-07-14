#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <vMAJOR.MINOR.PATCH[-PRERELEASE]> <protected-main-ref>" >&2
  exit 2
fi

TAG=$1
MAIN_REF=$2
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "release tag has an invalid name: $TAG" >&2
  exit 2
}
[[ $(git cat-file -t "refs/tags/$TAG") == tag ]] || {
  echo "release tag must be an annotated signed tag object" >&2
  exit 1
}
TAG_COMMIT=$(git rev-parse "refs/tags/$TAG^{}")
HEAD_COMMIT=$(git rev-parse HEAD)
[[ "$TAG_COMMIT" == "$HEAD_COMMIT" ]] || {
  echo "checked-out commit does not match the release tag" >&2
  exit 1
}
git rev-parse --verify "$MAIN_REF^{commit}" >/dev/null
git merge-base --is-ancestor "$TAG_COMMIT" "$MAIN_REF" || {
  echo "release tag is not reachable from protected main" >&2
  exit 1
}
git verify-tag "$TAG"
