#!/usr/bin/env bash
# W04 gate: fail if `cargo build --workspace --all-targets` emits any warning.
# Run before committing: `scripts/check-warnings.sh`.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Rebuilding workspace (all targets) to surface warnings..."
# Force a clean rebuild of the three crates so cached artifacts cannot hide
# warnings (audit §17.1: `Compiling` lines must be present).
cargo clean -p ssh-core -p ns-ssh -p ns-ssh-server 2>/dev/null || true
out=$(cargo build --workspace --all-targets 2>&1 || true)
count=$(printf '%s\n' "$out" | grep -cE 'warning:' || true)

if [ "$count" -gt 0 ]; then
    echo "==> FAIL: $count warning(s) found"
    printf '%s\n' "$out" | grep -E 'warning:' | head -30
    exit 1
fi

echo "==> OK: zero warnings"
