#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_IFACE="${1:-wlan0}"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi
  exec sudo "$0" "$@"
fi

echo "[SOPHIA] Running pre-flight monitor mode automation..."
airmon-ng check kill || true
airmon-ng start "$BASE_IFACE"

MON_IFACE="${BASE_IFACE}mon"
if ! iw dev "$MON_IFACE" info >/dev/null 2>&1; then
  if iw dev "$BASE_IFACE" info | grep -q "type monitor"; then
    MON_IFACE="$BASE_IFACE"
  fi
fi

if ! iw dev "$MON_IFACE" info >/dev/null 2>&1; then
  echo "[SOPHIA] Could not find monitor interface after airmon-ng start."
  exit 1
fi

cleanup() {
  echo "\n[SOPHIA] Stopping monitor mode on $MON_IFACE"
  airmon-ng stop "$MON_IFACE" || true
  if systemctl list-unit-files | grep -q '^NetworkManager.service'; then
    systemctl restart NetworkManager || true
  fi
}

trap cleanup EXIT

cd "$SCRIPT_DIR"
echo "[SOPHIA] Launching Web HUD on http://127.0.0.1:5000"
( sleep 1.2; xdg-open "http://127.0.0.1:5000" >/dev/null 2>&1 || true ) &
python3 "$SCRIPT_DIR/sophia.py" --iface "$MON_IFACE" --host 127.0.0.1 --port 5000
