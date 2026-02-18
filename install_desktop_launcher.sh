#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START_DESKTOP_FILE="$HOME/Desktop/SOPHIA WiFi Radar.desktop"
STOP_DESKTOP_FILE="$HOME/Desktop/SOPHIA WiFi Radar Shutdown.desktop"

chmod +x "$SCRIPT_DIR/launch_sophia.sh"
chmod +x "$SCRIPT_DIR/shutdown_sophia.sh"

cat > "$START_DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=SOPHIA WiFi Radar
Comment=Launch SOPHIA Wi-Fi Recon Radar
Exec=$SCRIPT_DIR/launch_sophia.sh wlan0
Path=$SCRIPT_DIR
Terminal=true
Categories=Network;Security;
EOF

cat > "$STOP_DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=SOPHIA WiFi Radar Shutdown
Comment=Restore normal Wi-Fi and internet after monitor mode
Exec=$SCRIPT_DIR/shutdown_sophia.sh wlan0
Path=$SCRIPT_DIR
Terminal=true
Categories=Network;Security;
EOF

chmod +x "$START_DESKTOP_FILE" "$STOP_DESKTOP_FILE"

if command -v gio >/dev/null 2>&1; then
  gio set "$START_DESKTOP_FILE" metadata::trusted true || true
  gio set "$STOP_DESKTOP_FILE" metadata::trusted true || true
fi

echo "Created desktop launcher: $START_DESKTOP_FILE"
echo "Created desktop launcher: $STOP_DESKTOP_FILE"
echo "Use start icon to launch SOPHIA and shutdown icon to restore Wi-Fi."
