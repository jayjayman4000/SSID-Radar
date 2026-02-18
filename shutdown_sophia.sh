#!/usr/bin/env bash
set -euo pipefail

BASE_IFACE="${1:-wlan0}"
MON_IFACE="${2:-${BASE_IFACE}mon}"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi
  exec sudo "$0" "$@"
fi

echo "[SOPHIA] Restoring Wi-Fi networking..."

if command -v airmon-ng >/dev/null 2>&1; then
  if iw dev "$MON_IFACE" info >/dev/null 2>&1; then
    echo "[SOPHIA] Stopping monitor interface: $MON_IFACE"
    airmon-ng stop "$MON_IFACE" || true
  fi
fi

if iw dev "$BASE_IFACE" info >/dev/null 2>&1; then
  echo "[SOPHIA] Setting $BASE_IFACE to managed mode"
  ip link set "$BASE_IFACE" down || true
  iw dev "$BASE_IFACE" set type managed || true
  ip link set "$BASE_IFACE" up || true
fi

if systemctl list-unit-files | grep -q '^NetworkManager.service'; then
  echo "[SOPHIA] Restarting NetworkManager"
  systemctl restart NetworkManager || true
fi

if systemctl list-unit-files | grep -q '^wpa_supplicant.service'; then
  echo "[SOPHIA] Restarting wpa_supplicant"
  systemctl restart wpa_supplicant || true
fi

echo "[SOPHIA] Done. Internet should be available again in a few seconds."
