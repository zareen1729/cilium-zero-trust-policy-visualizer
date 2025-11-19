#!/usr/bin/env bash
# scripts/demo.sh
# Simple end-to-end demo (host mode, non-containerized)
# Usage: sudo ./scripts/demo.sh eth0

set -euo pipefail

IFACE="${1:-eth0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[demo] Using interface: ${IFACE}"
echo "[demo] Loading eBPF program and starting API..."

pushd "${ROOT_DIR}/user" >/dev/null
sudo python3 loader.py --iface "${IFACE}" --policy ./config/policy.yaml &
LOADER_PID=$!
popd >/dev/null

sleep 3
echo "[demo] Loader running with PID ${LOADER_PID}"
echo "[demo] Open http://localhost:8080 in your browser."
echo "[demo] Generate some traffic that matches policy (e.g., curl between hosts)."

read -p "[demo] Press Enter to stop demo..."
sudo kill "${LOADER_PID}" || true
