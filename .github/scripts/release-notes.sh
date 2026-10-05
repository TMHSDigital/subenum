#!/usr/bin/env bash
# Prints the CHANGELOG.md section for a release tag, e.g. v1.2.3 prints the
# body under "## [1.2.3]". Used as GoReleaser's --release-notes (#61).
set -euo pipefail
version="${1#v}"
notes=$(awk -v v="$version" '
  /^## \[/ { if (found) exit; found = (index($0, "## [" v "]") == 1); next }
  found { print }
' CHANGELOG.md)
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no section for $1 (expected a '## [$version]' heading)" >&2
  exit 1
fi
printf '%s\n' "$notes"
