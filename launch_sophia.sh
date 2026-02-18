#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_IFACE="${1:-wlan0}"

detect_base_iface() {
  local iface
  iface="$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' | grep -E '^wl' | head -n1 || true)"
  echo "$iface"
}

find_monitor_iface() {
  local iface
  iface="$(iw dev 2>/dev/null | awk '/Interface/ {cur=$2} /type monitor/ {print cur; exit}')"
  echo "$iface"
}

if [[ "${EUID}" -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi
  exec sudo "$0" "$@"
fi

if ! iw dev "$BASE_IFACE" info >/dev/null 2>&1; then
  AUTO_IFACE="$(detect_base_iface)"
  if [[ -n "$AUTO_IFACE" ]]; then
    echo "[SOPHIA] '$BASE_IFACE' not found, using '$AUTO_IFACE'"
    BASE_IFACE="$AUTO_IFACE"
  fi
fi

if ! iw dev "$BASE_IFACE" info >/dev/null 2>&1; then
  echo "[SOPHIA] No usable base Wi-Fi interface found."
  echo "[SOPHIA] Try: ./launch_sophia.sh <your_iface>"
  exit 1
fi

echo "[SOPHIA] Running pre-flight monitor mode automation..."
airmon-ng check kill || true

if iw dev "$BASE_IFACE" info | grep -q "type monitor"; then
  echo "[SOPHIA] Interface '$BASE_IFACE' already in monitor mode"
else
  if ! airmon-ng start "$BASE_IFACE"; then
    echo "[SOPHIA] airmon-ng start failed; attempting to continue with existing monitor interface"
  fi
fi

MON_IFACE="${BASE_IFACE}mon"
if ! iw dev "$MON_IFACE" info >/dev/null 2>&1; then
  if iw dev "$BASE_IFACE" info | grep -q "type monitor"; then
    MON_IFACE="$BASE_IFACE"
  else
    AUTO_MON_IFACE="$(find_monitor_iface)"
    if [[ -n "$AUTO_MON_IFACE" ]]; then
      MON_IFACE="$AUTO_MON_IFACE"
    fi
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
