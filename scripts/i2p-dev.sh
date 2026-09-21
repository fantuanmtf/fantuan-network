#!/usr/bin/env bash
# Local I2P development helper.
#
# Checks whether a local i2pd router with the SAM bridge enabled is
# reachable, and prints actionable instructions when it is not.
set -euo pipefail

SAM_ADDR="${SAM_ADDR:-127.0.0.1:7656}"

echo "== Fantuan I2P development environment =="
echo "SAM bridge target: ${SAM_ADDR}"

if pgrep -x i2pd >/dev/null 2>&1; then
    echo "[ok] i2pd process is running"
else
    echo "[warn] i2pd process not found"
    echo "       install i2pd and enable the SAM bridge, e.g.:"
    echo "       /etc/i2pd/i2pd.conf -> [sam] enabled = true"
fi

host="${SAM_ADDR%%:*}"
port="${SAM_ADDR##*:}"
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q "${host}:${port}"; then
    echo "[ok] SAM bridge is listening on ${SAM_ADDR}"
else
    echo "[warn] nothing is listening on ${SAM_ADDR}"
    exit 1
fi

echo
echo "Integration tests:"
echo "  cargo test -p fantuan-transport --features i2p-integration -- --ignored"
