#!/usr/bin/env bash
# Build Aegis as a Universal Binary (Intel + Apple Silicon) on macOS.
#
# Requires:
#   - Xcode Command Line Tools (`xcode-select --install`)
#   - Rust with rustup (https://rustup.rs)
#   - The two Apple targets (auto-installed below if missing)
#
# Output: target/macos/aegis (one universal binary).

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script must run on macOS" >&2
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup is required. Install from https://rustup.rs" >&2
  exit 1
fi

echo "==> Installing Apple targets (if missing)…"
rustup target add aarch64-apple-darwin x86_64-apple-darwin

echo "==> Building for Apple Silicon (aarch64-apple-darwin)…"
cargo build --release --target aarch64-apple-darwin

echo "==> Building for Intel (x86_64-apple-darwin)…"
cargo build --release --target x86_64-apple-darwin

echo "==> Creating universal binary via lipo…"
mkdir -p target/macos
lipo -create \
  target/aarch64-apple-darwin/release/aegis \
  target/x86_64-apple-darwin/release/aegis \
  -output target/macos/aegis

chmod 755 target/macos/aegis

# Ad-hoc code-signing. An unsigned binary has no stable identity, so macOS
# forgets the Keychain "Always Allow" choice and re-prompts for the login
# password on *every* keyring access. An ad-hoc signature (`--sign -`, no
# certificate needed) gives a stable cdhash, so the consent sticks across runs.
echo "==> Ad-hoc code-signing the binary…"
codesign --force --sign - target/macos/aegis
codesign --verify --verbose=2 target/macos/aegis || true

echo "==> Result:"
file target/macos/aegis
ls -lh target/macos/aegis
echo
echo "Universal binary ready at: target/macos/aegis"
echo "Test with: target/macos/aegis --version"
