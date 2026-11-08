#!/bin/bash
# Builds seid-bench, signs it ad hoc with the smartcard entitlement, and runs it.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build --product seid-bench
BIN="$(swift build --show-bin-path)/seid-bench"
codesign -f -s - --entitlements Sources/seid-bench/seid-bench.entitlements "$BIN"
exec "$BIN" "$@"
