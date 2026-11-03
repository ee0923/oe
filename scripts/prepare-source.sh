#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
dest=${1:?Usage: prepare-source.sh DESTINATION}
if [[ -e "$dest" || -L "$dest" ]]; then
  echo 'Source destination must not exist' >&2
  exit 1
fi

repository=$(jq -er '.repository' "$root/sources.lock.json")
commit=$(jq -er '.commit | select(test("^[0-9a-f]{40}$"))' "$root/sources.lock.json")
# Keep full history and tags for upstream Gradle versioning.
git clone --no-checkout -- "$repository" "$dest"
git -C "$dest" checkout --detach "$commit"
test "$(git -C "$dest" rev-parse HEAD)" = "$commit"
git -C "$dest" submodule update --init --recursive
