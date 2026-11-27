#!/bin/bash
# passkey-vault deployment gate (macOS example).
#
#   sudo /Library/PasskeyVault/bin/deploy <repository path> <40-char commit hash>
#
# - Run the root-owned copy installed by install.sh, never the copy in the repository: the
#   repository is writable by the requester's account (see docs/deployment.md).
# - git runs as the invoking user only, so root never reads a user-controlled .git/config.
# - The diff shown is between the files that will actually be deployed and the running release,
#   not a git diff.
# - Never pulls "latest". Takes a full commit hash and asks the operator to type its first 8 chars.
#
# Test mode (not root): PV_TEST_MODE=1 PV_PREFIX=<dir> PV_PYTHON=<python> [PV_ASSUME_YES=1]
#   skips the root check, ownership changes and launchctl. All PV_* variables are ignored as root.

set -euo pipefail
umask 022
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=en_US.UTF-8

LABEL="com.passkey-vault.server"
PY_VERSION="3.15"

if [[ $EUID -eq 0 ]]; then
  TEST_MODE=0
  PREFIX="/Library/PasskeyVault"
  PYTHON="/Library/Frameworks/Python.framework/Versions/${PY_VERSION}/bin/python${PY_VERSION}"
  ASSUME_YES=0
else
  if [[ "${PV_TEST_MODE:-}" != "1" || -z "${PV_PREFIX:-}" || -z "${PV_PYTHON:-}" ]]; then
    echo "run as root: sudo /Library/PasskeyVault/bin/deploy <repository> <commit>" >&2
    exit 2
  fi
  TEST_MODE=1
  PREFIX="$PV_PREFIX"
  PYTHON="$PV_PYTHON"
  ASSUME_YES="${PV_ASSUME_YES:-0}"
fi

die() { echo "aborted: $*" >&2; exit 1; }
say() { echo "==> $*"; }

[[ $# -eq 2 ]] || die "usage: deploy <repository path> <40-char commit hash>"
REPO="$1"
COMMIT="$2"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "pass the full lowercase 40-char commit hash (no short hashes or branch names)"
[[ -d "$PREFIX/releases" && -d "$PREFIX/data" ]] || die "$PREFIX is not installed; run install.sh first"

# ---- read the commit from the repository (as the invoking user) ----
run_git() {
  local envs=(env -i PATH=/usr/bin:/bin HOME=/var/empty GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
              GIT_TERMINAL_PROMPT=0 LC_ALL=C)
  if [[ $TEST_MODE -eq 1 ]]; then
    "${envs[@]}" /usr/bin/git -C "$REPO" -c core.fsmonitor=false -c safe.directory="$REPO" "$@"
  else
    [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || die "cannot tell which user invoked sudo"
    /usr/bin/sudo -u "$SUDO_USER" "${envs[@]}" /usr/bin/git -C "$REPO" -c core.fsmonitor=false "$@"
  fi
}

resolved="$(run_git rev-parse --verify --quiet "${COMMIT}^{commit}" || true)"
[[ "$resolved" == "$COMMIT" ]] || die "commit $COMMIT not found in the repository"
say "commit $COMMIT"
run_git log -1 --format='    %an, %ad%n    %s' "$COMMIT"

STAGE="$(mktemp -d "$PREFIX/.stage.XXXXXX")"
DIFF_FILE="$(mktemp "$PREFIX/.diff.XXXXXX")"
cleanup() { rm -rf "$STAGE" "$DIFF_FILE"; }
trap cleanup EXIT

run_git archive --format=tar "$COMMIT" packages/server/src deploy LICENSE \
  | /usr/bin/tar -x --no-same-owner --no-same-permissions -f - -C "$STAGE"

# Only regular files and directories (no symlinks or devices).
special="$(find "$STAGE" ! -type f ! -type d -print | head -5)"
[[ -z "$special" ]] || die "archive contains non-regular entries: $special"

# ---- diff: files to be deployed vs. the running release ----
CURRENT="$PREFIX/current"
if [[ -L "$CURRENT" ]]; then
  BASE="$(cd "$CURRENT" && pwd -P)"
  say "running release: $(basename "$BASE")"
else
  BASE="/var/empty"
  say "no running release (first deployment): every file is new"
fi
set +e
/usr/bin/diff -ruN -x __pycache__ "$BASE" "$STAGE" > "$DIFF_FILE"
diff_status=$?
set -e
[[ $diff_status -le 1 ]] || die "diff failed"

say "changed files:"
/usr/bin/diff -rqN -x __pycache__ "$BASE" "$STAGE" | sed -e "s|$BASE/||g" -e "s|$STAGE/||g" -e 's/^/    /' || true
echo "    (changed lines: $(grep -c '^[+-]' "$DIFF_FILE" || true))"

SELF_REL="deploy/macos/deploy.sh"
if [[ -L "$CURRENT" ]] && ! cmp -s "$BASE/$SELF_REL" "$STAGE/$SELF_REL"; then
  echo
  echo "!!  $SELF_REL changed. This run still uses the installed (reviewed) copy."
  echo "!!  To use the new one, review the diff and re-run the 'install deploy script' step of install.sh."
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  [[ -t 0 && -e /dev/tty ]] || die "run from a terminal (confirmation required)"
  echo
  read -r -p "Show the full diff? (opens less; q to close) [Y/n] " show </dev/tty
  if [[ "$show" != "n" && "$show" != "N" ]]; then
    /usr/bin/less -R "$DIFF_FILE" </dev/tty
  fi
  read -r -p "Type the first 8 characters of the commit (${COMMIT:0:8}) to deploy: " confirm </dev/tty
  [[ "$confirm" == "${COMMIT:0:8}" ]] || die "confirmation did not match; nothing deployed"
fi

# ---- the interpreter must be root-owned and not group/world writable ----
[[ -x "$PYTHON" ]] || die "Python not found: $PYTHON (install ${PY_VERSION} with the python.org installer)"
if [[ $TEST_MODE -eq 0 ]]; then
  PY_ROOT="/Library/Frameworks/Python.framework/Versions/${PY_VERSION}"
  bad="$(find /Library/Frameworks/Python.framework -maxdepth 0 \( ! -user root -o -perm -g+w -o -perm -o+w \) -print;
         find "$PY_ROOT" ! -type l \( ! -user root -o -perm -g+w -o -perm -o+w \) -print | head -5)"
  [[ -z "$bad" ]] || die "Python files are writable by non-root accounts (e.g. $bad).
  Lock them down first (docs/deployment.md):
    sudo chown -R root:wheel $PY_ROOT && sudo chmod -R go-w $PY_ROOT"
fi

# ---- virtualenv: one per lock-file hash, wheels only, hashes verified ----
LOCK="$STAGE/deploy/requirements.lock"
LOCK_HASH="$(shasum -a 256 "$LOCK" | cut -c1-16)"
VENV="$PREFIX/venvs/py${PY_VERSION}-$LOCK_HASH"
if [[ ! -d "$VENV" ]]; then
  say "installing dependencies into $VENV"
  rm -rf "$VENV.tmp"
  "$PYTHON" -I -m venv "$VENV.tmp"
  "$VENV.tmp/bin/python" -I -m pip install --quiet --no-input --disable-pip-version-check \
      --require-hashes --no-deps --only-binary :all: -r "$LOCK"
  mv "$VENV.tmp" "$VENV"
fi
"$VENV/bin/python" -I -c "import webauthn, cryptography" || die "virtualenv check failed"

# ---- place the release ----
RELEASE="$PREFIX/releases/$COMMIT"
rm -rf "$RELEASE"
mv "$STAGE" "$RELEASE"
trap 'rm -f "$DIFF_FILE"' EXIT
chmod -R u=rwX,go=rX "$RELEASE" "$VENV"
if [[ $TEST_MODE -eq 0 ]]; then
  chown -R root:wheel "$RELEASE" "$VENV"
fi

# The placed code must import with the placed virtualenv.
"$VENV/bin/python" -I -B -c "import sys; sys.path.insert(0, sys.argv[1]); import passkey_vault.app" "$RELEASE/packages/server/src" \
  || die "the placed code does not import"

ln -shf "releases/$COMMIT" "$PREFIX/current"
ln -shf "venvs/$(basename "$VENV")" "$PREFIX/venv"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $COMMIT ${SUDO_USER:-test}" >> "$PREFIX/deploy.log"
say "placed: current -> releases/$COMMIT"

# ---- restart ----
if [[ $TEST_MODE -eq 0 ]]; then
  PLIST="/Library/LaunchDaemons/$LABEL.plist"
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    launchctl kickstart -k "system/$LABEL"
    say "restarted"
  else
    launchctl bootstrap system "$PLIST"
    say "registered with launchd and started"
  fi
  sleep 1
  launchctl print "system/$LABEL" | grep -E "state =|pid =" || true
fi
say "done. server log: $PREFIX/logs/server.log, audit log: $PREFIX/data/audit.log (read with sudo)"
