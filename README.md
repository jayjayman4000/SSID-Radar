# SOPHIA Wi-Fi Recon Radar

covers home networks, police cruisers, flock cameras etc.

## What this build includes

- Flask Web HUD (`templates/index.html`) with tactical blue radar map
- Threaded Scapy sniffer + Flask server in one script (`sophia.py`)
- In-script channel hopping (1-13 2.4GHz, full 5GHz band, or all channels in dual mode)
- Live channel controls (2.4GHz / 5GHz / dual, hop delay, lock channel)
  - **Dual mode now scans all 2.4GHz + 5GHz channels** for comprehensive coverage
- High-risk classification for FLOCK / police-like / security camera signatures
- HUD toggle to ignore dorm/home-like networks (including SSIDs with 10+ matching names)
- **Radar click selection**: Click on radar pings to open action menu
  - Select networks as SOI (Signals of Interest) targets
  - Hide networks from radar and list display
  - Selected target is persisted and saved to `selected_target.json`
- **Selected Target display panel** showing current SOI with BSSID and risk level
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

If your adapter is not named `wlan0` (for example `wlp2s0`), run:

```bash
./launch_sophia.sh wlp2s0
```

## Radar HUD Usage

- **Click on radar pings** to see action menu (Select as target, Hide network)
- **Hidden networks** are persisted in browser localStorage
- **Selected targets** are saved server-side to `selected_target.json`
- **Channel controls** allow switching between 2.4GHz, 5GHz, or Dual (all channels)
- **Zoom slider** scales the radar display (0.6x to 2.2x)
- **Alert rules** let you filter by RSSI, confidence, and network category

## Restore normal Wi-Fi / internet

If monitor mode stays active and internet is down, run:

```bash
./shutdown_sophia.sh wlan0
```

## About N/S/E/W orientation

Current radar direction is visual/simulated (stable hash angle per BSSID), not true physical bearing.
To get true N/S/E/W orientation to a transmitter, you need additional direction hardware
(directional antennas, phased arrays, or multi-receiver triangulation with heading sensors).

## API Endpoints

- `GET/POST /api/networks` - Fetch detected networks
- `GET/POST /api/networks/longpoll` - Long-poll for network updates
- `GET/POST /api/channel` - Get/set channel hopping configuration
- `GET/POST /api/target` - Get/set selected SOI target
- `GET/POST /api/movement` - Get/post GPS movement breadcrumbs

HUD URL:

`http://127.0.0.1:5000`
