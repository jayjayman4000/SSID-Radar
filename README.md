# SOPHIA Wi-Fi Recon Radar

covers home networks, police cruisers, flock cameras etc.

## What this build includes

- Flask Web HUD (`templates/index.html`) with tactical blue radar map
- Threaded Scapy sniffer + Flask server in one script (`sophia.py`)
- In-script channel hopping (1-13) so no second terminal is needed
- Live channel controls (2.4GHz / 5GHz / dual, hop delay, lock channel)
- High-risk classification for FLOCK / police-like / security camera signatures
- HUD toggle to ignore dorm/home-like networks (including SSIDs with 10+ matching names)
- Audible beep alerts for newly detected high-risk targets
- HUD zoom slider to change radar scale
- Confidence scoring per target (signal + repeat sightings + stability + freshness)
- Alert rules panel (minimum RSSI, minimum confidence, category targeting)
- Movement mode with GPS path logging and strongest-network breadcrumbs
- Launcher script (`launch_sophia.sh`) that runs:
  - `airmon-ng check kill`
  - `airmon-ng start <iface>`
  - `python3 sophia.py --iface <monitor_iface>`

## Kali setup (one time)

```bash
python3 -m pip install -r requirements.txt
chmod +x launch_sophia.sh
chmod +x shutdown_sophia.sh
chmod +x install_desktop_launcher.sh
./install_desktop_launcher.sh
```

Then double-click `SOPHIA WiFi Radar` on the Kali desktop.

To restore normal networking, double-click `SOPHIA WiFi Radar Shutdown`.

## Direct run

```bash
./launch_sophia.sh wlan0
```

## Restore normal Wi-Fi / internet

If monitor mode stays active and internet is down, run:

```bash
./shutdown_sophia.sh wlan0
```

## About N/S/E/W orientation

Current radar direction is visual/simulated (stable hash angle per BSSID), not true physical bearing.
To get true N/S/E/W orientation to a transmitter, you need additional direction hardware
(directional antennas, phased arrays, or multi-receiver triangulation with heading sensors).

HUD URL:

`http://127.0.0.1:5000`
