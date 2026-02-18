# SOPHIA Wi-Fi Recon Radar

covers home networks, police cruisers, flock cameras etc.

## What this build includes

- Flask Web HUD (`templates/index.html`) with tactical blue radar map
- Threaded Scapy sniffer + Flask server in one script (`sophia.py`)
- In-script channel hopping (1-13) so no second terminal is needed
- Launcher script (`launch_sophia.sh`) that runs:
  - `airmon-ng check kill`
  - `airmon-ng start <iface>`
  - `python3 sophia.py --iface <monitor_iface>`

## Kali setup (one time)

```bash
python3 -m pip install -r requirements.txt
chmod +x launch_sophia.sh
chmod +x install_desktop_launcher.sh
./install_desktop_launcher.sh
```

Then double-click `SOPHIA WiFi Radar` on the Kali desktop.

## Direct run

```bash
./launch_sophia.sh wlan0
```

HUD URL:

`http://127.0.0.1:5000`
