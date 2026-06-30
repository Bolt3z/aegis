#!/usr/bin/env bash
# Build a macOS .pkg installer for Aegis (universal binary + Finder Quick Actions).
#
# Output: target/macos/aegis-<version>-universal.pkg
#
# The .pkg, when installed:
#   - copies the universal `aegis` binary to /usr/local/bin/aegis
#   - copies three .workflow bundles to /Library/Services/ (system-wide
#     Quick Actions visible to all users in Finder right-click)
#
# Requires:
#   - macOS (uses pkgbuild)
#   - target/macos/aegis already built by build-macos-universal.sh

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script must run on macOS" >&2
  exit 1
fi

VERSION="$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')"
BIN_PATH="target/macos/aegis"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "error: universal binary not found at $BIN_PATH" >&2
  echo "       run scripts/build-macos-universal.sh first" >&2
  exit 1
fi

STAGING="$(mktemp -d -t aegis-staging.XXXXXX)"
trap "rm -rf '$STAGING'" EXIT

# `mktemp -d` on macOS creates the staging root with mode 700, which can
# bleed into the .pkg payload and leave /Library/Services unreadable by
# non-root processes (launchd / pbs cannot register the workflows then).
# Force world-readable up front and again at the end.
chmod 755 "$STAGING"

echo "==> Staging at $STAGING"

# Binary
mkdir -p "$STAGING/usr/local/bin"
cp "$BIN_PATH" "$STAGING/usr/local/bin/aegis"
chmod 755 "$STAGING/usr/local/bin/aegis"

# Finder Quick Actions (system-wide, visible to all users)
mkdir -p "$STAGING/Library/Services"
cp -R "packaging/macos/services/"*.workflow "$STAGING/Library/Services/"

# Belt-and-suspenders: enforce 755 on every directory and 644 on every
# regular file inside the staging tree, so pkgbuild can't bake a
# restrictive mode into the .pkg payload.
find "$STAGING" -type d -exec chmod 755 {} +
find "$STAGING" -type f -exec chmod 644 {} +
chmod 755 "$STAGING/usr/local/bin/aegis"

echo "==> Building .pkg…"
mkdir -p target/macos
PKG_OUT="target/macos/aegis-${VERSION}-universal.pkg"

pkgbuild \
  --root "$STAGING" \
  --identifier ch.c41.aegis \
  --version "$VERSION" \
  --install-location / \
  --ownership recommended \
  "$PKG_OUT"

echo
echo "==> Result:"
ls -lh "$PKG_OUT"
echo
echo "Install with:    sudo installer -pkg $PKG_OUT -target /"
echo "Or double-click the .pkg in Finder."
echo
echo "After install:"
echo "  - 'aegis' is in /usr/local/bin/ (already in PATH on macOS)"
echo "  - Finder right-click → Quick Actions / Services → Aegis - Encrypt / Decrypt / Info"
echo "  - The first time Finder may not show the services until you log out & in"
echo "    (or run /System/Library/CoreServices/pbs -update)"
