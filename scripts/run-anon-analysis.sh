#!/usr/bin/env bash
# Run an offline anonymity simulation and produce an English analysis report.
#
# Usage: scripts/run-anon-analysis.sh <scenario> [seed]
set -euo pipefail

SCENARIO="${1:-dcnet-3}"
SEED="${2:-1}"
OUT_DIR="${OUT_DIR:-reports}"
JSON="${OUT_DIR}/sim-${SCENARIO}-${SEED}.json"

mkdir -p "${OUT_DIR}"

echo "== running simulation: scenario=${SCENARIO} seed=${SEED} =="
cargo run --release -p fantuan-sim -- run \
    --scenario "${SCENARIO}" \
    --seed "${SEED}" \
    --out "${JSON}"

echo "== analysing simulation transcript =="
PYTHONPATH="${PYTHONPATH:-analysis/src}" python3 -m fantuan_analysis \
    --input "${JSON}" \
    --out "${OUT_DIR}/anonymity-${SCENARIO}-${SEED}.md"

echo "== done =="
