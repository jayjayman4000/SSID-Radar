#!/usr/bin/env bash
set -euo pipefail

BASE_IFACE="${1:-}"
MON_IFACE="${2:-}"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi
  exec sudo "$0" "$@"
fi

echo "[SOPHIA] Restoring Wi-Fi networking..."

detect_monitor_iface() {
  local monitor_iface
  monitor_iface="$(iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type monitor/ {print iface; exit}')"
  echo "$monitor_iface"
}

detect_base_iface() {
  local base_iface
  base_iface="$(iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type managed/ {print iface; exit}')"
  if [[ -n "$base_iface" ]]; then
    echo "$base_iface"
    return
  fi

  base_iface="$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' | grep -E '^wl' | head -n1 || true)"
  echo "$base_iface"
}

if [[ -z "$MON_IFACE" ]]; then
  MON_IFACE="$(detect_monitor_iface)"
fi

if [[ -z "$BASE_IFACE" ]]; then
  if [[ -n "$MON_IFACE" && "$MON_IFACE" == *mon ]]; then
    BASE_IFACE="${MON_IFACE%mon}"
  else
    BASE_IFACE="$(detect_base_iface)"
  fi
fi

if [[ -z "$BASE_IFACE" ]]; then
  BASE_IFACE="wlan0"
fi

if command -v airmon-ng >/dev/null 2>&1; then
  if [[ -n "$MON_IFACE" ]] && iw dev "$MON_IFACE" info >/dev/null 2>&1; then
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

if command -v rfkill >/dev/null 2>&1; then
  rfkill unblock wifi || true
fi

if command -v nmcli >/dev/null 2>&1; then
  nmcli radio wifi on || true
fi

if systemctl list-unit-files | grep -q '^NetworkManager.service'; then
  echo "[SOPHIA] Restarting NetworkManager"
  systemctl restart NetworkManager || true
fi

if systemctl list-unit-files | grep -q '^wpa_supplicant.service'; then
  echo "[SOPHIA] Restarting wpa_supplicant"
  systemctl restart wpa_supplicant || true
fi

if command -v dhclient >/dev/null 2>&1; then
  dhclient "$BASE_IFACE" || true
fi

echo "[SOPHIA] Done. Internet should be available again in a few seconds."
