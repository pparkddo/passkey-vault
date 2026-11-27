#!/bin/bash
# Release versioning for the two packages, which always share one version.
#
#   scripts/version.sh show            print the current version
#   scripts/version.sh set 0.2.0       set both packages to 0.2.0 and refresh uv.lock
#   scripts/version.sh check [v0.2.0]  fail unless both packages (and the tag, if given) agree and
#                                      CHANGELOG.md has a "## [0.2.0]" section
set -euo pipefail
cd "$(dirname "$0")/.."

PACKAGES=(passkey-vault-server passkey-vault-client)

version_of() { uv version --package "$1" --short; }

case "${1:-}" in
  show)
    version_of "${PACKAGES[0]}"
    ;;
  set)
    new="${2:?usage: scripts/version.sh set X.Y.Z}"
    [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+([ab]|rc)?[0-9]*$ ]] || { echo "not a version: $new" >&2; exit 2; }
    for p in "${PACKAGES[@]}"; do uv version --package "$p" "$new" --frozen >/dev/null; done
    uv lock --quiet
    echo "both packages are now $new; add a '## [$new] - YYYY-MM-DD' section to CHANGELOG.md"
    ;;
  check)
    server="$(version_of passkey-vault-server)"
    client="$(version_of passkey-vault-client)"
    [[ "$server" == "$client" ]] || { echo "package versions differ: server $server, client $client" >&2; exit 1; }
    if [[ -n "${2:-}" ]]; then
      [[ "${2#v}" == "$server" ]] || { echo "tag $2 does not match package version $server" >&2; exit 1; }
    fi
    grep -q "^## \[$server\]" CHANGELOG.md || { echo "CHANGELOG.md has no '## [$server]' section" >&2; exit 1; }
    echo "$server"
    ;;
  notes)
    # Print the CHANGELOG section for a version (used as release notes).
    v="${2:?usage: scripts/version.sh notes X.Y.Z}"
    awk -v v="$v" '$0 ~ "^## \\[" v "\\]" {on=1; next} on && /^## \[/ {exit} on {print}' CHANGELOG.md
    ;;
  *)
    sed -n '2,8p' "$0" >&2
    exit 2
    ;;
esac
