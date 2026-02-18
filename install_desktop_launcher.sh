#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_FILE="$HOME/Desktop/SOPHIA WiFi Radar.desktop"

chmod +x "$SCRIPT_DIR/launch_sophia.sh"

cat > "$DESKTOP_FILE" <<EOF
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

chmod +x "$DESKTOP_FILE"

if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_FILE" metadata::trusted true || true
fi

echo "Created desktop launcher: $DESKTOP_FILE"
echo "Double-click it from Kali desktop to start SOPHIA."
