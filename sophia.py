import argparse
import hashlib
import os
import subprocess
import threading
import time
from typing import Dict, List

from flask import Flask, jsonify, render_template, request
from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp


app = Flask(__name__, template_folder="templates")
device_lock = threading.RLock()
update_condition = threading.Condition(device_lock)
detected_devices: Dict[str, dict] = {}
data_version = 0

FLOCK_KEYWORDS = ["flock", "falcon", "lpr", "plate", "flocksafety"]
CAMERA_KEYWORDS = [
    "camera",
    "cam",
    "cctv",
    "hikvision",
    "dahua",
    "axis",
    "ring",
    "arlo",
    "nest cam",
    "reolink",
    "amcrest",
    "unifi-video",
    "surveillance",
]
POLICE_KEYWORDS = [
    "police",
    "sheriff",
    "state patrol",
    "highway patrol",
    "public safety",
    "law enforcement",
    "marshal",
    "trooper",
    "county pd",
    "city pd",
    "leo",
]
HOME_KEYWORDS = [
    "home",
    "house",
    "apartment",
    "mywifi",
    "linksys",
    "netgear",
    "xfinity",
    "spectrum",
    "verizon",
    "att",
    "tp-link",
]


def calculate_distance(rssi: int, measure_power: float = -30.0) -> float:
    if rssi == 0:
        return -1.0
    n = 2.0
    ratio = (measure_power - rssi) / (10 * n)
    return round(10 ** ratio, 2)


def get_ssid(packet) -> str:
    try:
        raw = packet[Dot11Elt].info
        decoded = raw.decode("utf-8", errors="replace").strip()
        return decoded if decoded else "Hidden SSID"
    except Exception:
        return "Hidden SSID"


def get_crypto(packet) -> str:
    network_stats = get_network_stats(packet)
    if network_stats is None:
        return "UNKNOWN"

    try:
        crypto = network_stats.get("crypto", [])
        normalized = sorted(str(item).upper() for item in crypto)
        return ",".join(normalized) if normalized else "OPEN"
    except Exception:
        return "UNKNOWN"


def get_channel(packet) -> int:
    network_stats = get_network_stats(packet)
    if network_stats is not None:
        try:
            channel = network_stats.get("channel")
            if channel is not None:
                return int(channel)
        except Exception:
            pass

    try:
        element = packet.getlayer(Dot11Elt)
        while element is not None:
            if getattr(element, "ID", None) == 3 and hasattr(element, "info") and element.info:
                return int(element.info[0])
            element = element.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return -1


def get_network_stats(packet):
    try:
        if packet.haslayer(Dot11Beacon):
            return packet[Dot11Beacon].network_stats()
        if packet.haslayer(Dot11ProbeResp):
            return packet[Dot11ProbeResp].network_stats()
    except Exception:
        return None
    return None


def score_risk(ssid: str, crypto: str) -> str:
    lowered = ssid.lower()
    crypto_upper = crypto.upper()
    if "OPEN" in crypto_upper or "UNKNOWN" in crypto_upper or "WEP" in crypto_upper:
        return "HIGH"
    if any(keyword in lowered for keyword in ["free", "public", "guest", "airport", "hotel"]):
        return "HIGH"
    if any(keyword in lowered for keyword in ["wifi", "internet", "cafe"]):
        return "MED"
    return "LOW"


def has_keyword(text: str, keywords: List[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def classify_network(ssid: str, crypto: str, bssid: str) -> tuple[str, str, List[str]]:
    lowered = ssid.lower()
    crypto_upper = crypto.upper()
    matches: List[str] = []

    if has_keyword(lowered, FLOCK_KEYWORDS):
        matches.append("flock-signature")
        return "HIGH", "FLOCK", matches

    if has_keyword(lowered, POLICE_KEYWORDS):
        matches.append("police-signature")
        return "HIGH", "POLICE", matches

    if has_keyword(lowered, CAMERA_KEYWORDS):
        matches.append("camera-signature")
        return "HIGH", "CAMERA", matches

    if has_keyword(lowered, HOME_KEYWORDS):
        matches.append("home-signature")
        return "LOW", "HOME", matches

    if "OPEN" in crypto_upper or "UNKNOWN" in crypto_upper or "WEP" in crypto_upper:
        matches.append("weak-or-open-crypto")
        return "HIGH", "OPEN", matches

    baseline_risk = score_risk(ssid, crypto)
    category = "GENERAL"
    if baseline_risk == "MED":
        category = "PUBLIC"
    return baseline_risk, category, matches


def update_device(packet, measure_power: float) -> None:
    global data_version

    if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return

    bssid = packet[Dot11].addr2
    if not bssid:
        return

    rssi = int(getattr(packet, "dBm_AntSignal", -100))
    ssid = get_ssid(packet)
    crypto = get_crypto(packet)
    channel = get_channel(packet)
    distance = calculate_distance(rssi, measure_power)
    risk, category, matches = classify_network(ssid, crypto, bssid)

    with update_condition:
        detected_devices[bssid] = {
            "bssid": bssid,
            "ssid": ssid,
            "rssi": rssi,
            "distance": distance,
            "risk": risk,
            "category": category,
            "matches": matches,
            "crypto": crypto,
            "channel": channel,
            "last_seen": time.time(),
        }
        data_version += 1
        update_condition.notify_all()


def build_radar_payload(max_distance: float = 60.0) -> List[dict]:
    now = time.time()
    payload = []
    stale_keys = []

    with device_lock:
        for bssid, info in detected_devices.items():
            age = now - info["last_seen"]
            if age > 90:
                stale_keys.append(bssid)
                continue

            angle_seed = int(hashlib.sha1(bssid.encode("utf-8")).hexdigest(), 16) % 360
            distance = info["distance"]
            if distance <= 0:
                normalized = 1.0
            else:
                normalized = min(distance / max_distance, 1.0)

            payload.append({
                **info,
                "age": round(age, 1),
                "angle": angle_seed,
                "normalized_distance": round(normalized, 3),
            })

        for key in stale_keys:
            del detected_devices[key]

    ssid_counts: Dict[str, int] = {}
    for item in payload:
        key = item["ssid"].strip().lower()
        if key == "":
            key = "hidden ssid"
        ssid_counts[key] = ssid_counts.get(key, 0) + 1

    for item in payload:
        key = item["ssid"].strip().lower()
        if key == "":
            key = "hidden ssid"
        item["same_ssid_count"] = ssid_counts.get(key, 1)

    payload.sort(key=lambda item: item["rssi"], reverse=True)
    return payload


def channel_hopper(interface_name: str, stop_event: threading.Event, hop_delay: float = 0.35) -> None:
    channels = [str(channel) for channel in range(1, 14)]
    index = 0

    while not stop_event.is_set():
        channel = channels[index % len(channels)]
        subprocess.run(
            ["iw", "dev", interface_name, "set", "channel", channel],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        index += 1
        time.sleep(hop_delay)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/networks")
def api_networks():
    return jsonify({
        "count": len(detected_devices),
        "networks": build_radar_payload(),
        "version": data_version,
        "timestamp": time.time(),
    })


@app.route("/api/networks/longpoll")
def api_networks_longpoll():
    global data_version

    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0

    try:
        timeout = float(request.args.get("timeout", "20"))
    except ValueError:
        timeout = 20.0

    timeout = max(1.0, min(timeout, 30.0))
    deadline = time.monotonic() + timeout

    with update_condition:
        while data_version <= since:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            update_condition.wait(timeout=remaining)
        current_version = data_version

    return jsonify({
        "count": len(detected_devices),
        "networks": build_radar_payload(),
        "version": current_version,
        "timestamp": time.time(),
    })


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SOPHIA Wi-Fi Recon Radar")
    parser.add_argument("--iface", default="wlan0mon", help="Monitor interface (default: wlan0mon)")
    parser.add_argument("--host", default="127.0.0.1", help="Web host (default: 127.0.0.1)")
    parser.add_argument("--port", default=5000, type=int, help="Web port (default: 5000)")
    parser.add_argument("--measure-power", default=-30.0, type=float, help="RSSI at 1 meter")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if os.name != "posix":
        raise SystemExit("This app is for Linux/Kali.")

    if os.geteuid() != 0:
        raise SystemExit("Run as root (sudo/pkexec) so sniffing and channel hopping can work.")

    stop_event = threading.Event()
    sniffer = AsyncSniffer(
        iface=args.iface,
        prn=lambda packet: update_device(packet, args.measure_power),
        store=False,
    )

    hopper_thread = threading.Thread(
        target=channel_hopper,
        args=(args.iface, stop_event),
        daemon=True,
    )

    print(f"[SOPHIA] Starting threaded sniffer on {args.iface}")
    print(f"[SOPHIA] Channel hopping enabled (1-13)")
    print(f"[SOPHIA] Web HUD: http://{args.host}:{args.port}")

    sniffer.start()
    hopper_thread.start()

    try:
        app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)
    finally:
        stop_event.set()
        if sniffer.running:
            sniffer.stop()


if __name__ == "__main__":
    main()