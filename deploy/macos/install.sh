#!/bin/bash
# passkey-vault one-time installation (macOS example). Read it, then run it yourself:
#
#   sudo bash deploy/macos/install.sh https://vault.example.com
#
# Steps (each asks for confirmation):
#   1. create a dedicated role account (_passkeyvault, no login)
#   2. create /Library/PasskeyVault (code root-owned; data and logs owned by the service account, 0700)
#   3. install a root-owned copy of the deploy script at /Library/PasskeyVault/bin/deploy
#   4. install the LaunchDaemon (not started yet; the first deploy starts it)
#
# This file lives in the repository, which the requester's account can modify. Review it before
# running it. Later deployments only use the root-owned copy:
#   sudo /Library/PasskeyVault/bin/deploy <repository> <commit>

set -euo pipefail
umask 022
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

PREFIX="/Library/PasskeyVault"
SERVICE_USER="_passkeyvault"
SERVICE_UID="${PV_SERVICE_UID:-470}"   # role accounts need a UID in 450-499
LABEL="com.passkey-vault.server"
HERE="$(cd "$(dirname "$0")" && pwd -P)"

die() { echo "aborted: $*" >&2; exit 1; }
step() {
  echo
  echo "==> $1"
  read -r -p "    continue? [y/N] " ok </dev/tty
  [[ "$ok" == "y" || "$ok" == "Y" ]]
}

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ $# -eq 1 ]] || die "usage: sudo bash deploy/macos/install.sh https://<approval host>"
ORIGIN="${1%/}"
[[ "$ORIGIN" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || die "origin must look like https://host[:port]"

if step "1. create the role account $SERVICE_USER (UID $SERVICE_UID)"; then
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "    already exists: $(id "$SERVICE_USER")"
  else
    if dscl . -list /Users UniqueID | awk -v u="$SERVICE_UID" '$2==u {found=1} END {exit !found}'; then
      die "UID $SERVICE_UID is taken; re-run with PV_SERVICE_UID=<a free value in 450-499>"
    fi
    sysadminctl -addUser "$SERVICE_USER" -fullName "passkey-vault service" -UID "$SERVICE_UID" \
      -shell /usr/bin/false -home /var/empty -roleAccount
    id "$SERVICE_USER"
  fi
fi

if step "2. create $PREFIX"; then
  install -d -o root -g wheel -m 755 "$PREFIX" "$PREFIX/bin" "$PREFIX/releases" "$PREFIX/venvs"
  install -d -o "$SERVICE_USER" -m 700 "$PREFIX/data" "$PREFIX/logs"
  ls -la "$PREFIX"
fi

if step "3. install a root-owned copy of the deploy script ($PREFIX/bin/deploy). Have you read $HERE/deploy.sh?"; then
  install -o root -g wheel -m 755 "$HERE/deploy.sh" "$PREFIX/bin/deploy"
  shasum -a 256 "$PREFIX/bin/deploy"
fi

if step "4. install the LaunchDaemon (/Library/LaunchDaemons/$LABEL.plist, origin=$ORIGIN)"; then
  tmp="$(mktemp)"
  sed -e "s|__PREFIX__|$PREFIX|g" -e "s|__ORIGIN__|$ORIGIN|g" -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
    "$HERE/com.passkey-vault.server.plist" > "$tmp"
  plutil -lint "$tmp"
  install -o root -g wheel -m 644 "$tmp" "/Library/LaunchDaemons/$LABEL.plist"
  rm -f "$tmp"
fi

echo
echo "installed. next: sudo $PREFIX/bin/deploy <repository path> <40-char commit>"
