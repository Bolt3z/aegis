#!/usr/bin/env bash
# Convenience wrapper: build universal binary + .pkg in one shot.
set -euo pipefail
cd "$(dirname "$0")/.."

bash scripts/build-macos-universal.sh
echo
bash scripts/build-pkg.sh
