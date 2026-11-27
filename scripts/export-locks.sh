#!/bin/bash
# Regenerate the hash-pinned server lock files used by the Dockerfile and the macOS deploy script.
# Run after anything changes uv.lock (including Dependabot updates). With --check, only compare.
set -euo pipefail
cd "$(dirname "$0")/.."

export_lock() {
  uv export --package passkey-vault-server --no-emit-workspace --no-dev --format requirements-txt --quiet "$@"
}

if [[ "${1:-}" == "--check" ]]; then
  export_lock | diff -u deploy/requirements.lock - || { echo "run scripts/export-locks.sh" >&2; exit 1; }
  export_lock --extra postgres --extra mongodb | diff -u deploy/requirements-db.lock - \
    || { echo "run scripts/export-locks.sh" >&2; exit 1; }
else
  export_lock > deploy/requirements.lock
  export_lock --extra postgres --extra mongodb > deploy/requirements-db.lock
fi
