import argparse
import hashlib
import statistics
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
movement_points: List[dict] = []

CHANNEL_STATE = {
    "mode": "2.4GHz",
    "enabled": True,
    "locked_channel": None,
    "hop_delay": 0.35,
    "current_channel": None,
}

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

CHANNEL_LISTS = {
    "2.4GHz": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    "5GHz": [36, 40, 44, 48, 149, 153, 157, 161],
    "dual": [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161],
}

MAX_DISPLAY_DISTANCE_M = 180.0
RSSI_HISTORY_SIZE = 9


def calculate_distance(rssi: int, measure_power: float = -30.0) -> float:
    if rssi == 0:
        return -1.0
    n = 2.0
    ratio = (measure_power - rssi) / (10 * n)
    return round(10 ** ratio, 2)


def robust_distance_from_rssi(rssi_history: List[int], measure_power: float) -> tuple[float, int]:
    if not rssi_history:
        return -1.0, -100

    stable_rssi = int(round(statistics.median(rssi_history)))
    distance = calculate_distance(stable_rssi, measure_power)
    if distance < 0:
        return distance, stable_rssi

    return round(min(distance, MAX_DISPLAY_DISTANCE_M), 2), stable_rssi


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


def compute_confidence(rssi: int, sightings: int, avg_rssi: float, jitter: float, age_seconds: float) -> int:
    signal_score = max(0.0, min(1.0, (rssi + 100) / 45.0))
    repeat_score = max(0.0, min(1.0, sightings / 12.0))
    consistency_score = max(0.0, min(1.0, 1.0 - (jitter / 20.0)))
    freshness_score = max(0.0, min(1.0, 1.0 - (age_seconds / 120.0)))
    score = (
        signal_score * 0.35
        + repeat_score * 0.25
        + consistency_score * 0.25
        + freshness_score * 0.15
    )
    return int(round(score * 100))


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
    risk, category, matches = classify_network(ssid, crypto, bssid)

    now = time.time()

    with update_condition:
        previous = detected_devices.get(bssid)
        sightings = 1
        first_seen = now
        avg_rssi = float(rssi)
        jitter = 0.0
        rssi_history: List[int] = []
        if previous:
            sightings = int(previous.get("sightings", 1)) + 1
            first_seen = float(previous.get("first_seen", now))
            prev_avg = float(previous.get("avg_rssi", rssi))
            avg_rssi = prev_avg + ((rssi - prev_avg) / max(sightings, 1))
            prev_jitter = float(previous.get("rssi_jitter", 0.0))
            jitter = (prev_jitter * 0.7) + (abs(rssi - prev_avg) * 0.3)
            rssi_history = list(previous.get("rssi_history", []))

        rssi_history.append(rssi)
        if len(rssi_history) > RSSI_HISTORY_SIZE:
            rssi_history = rssi_history[-RSSI_HISTORY_SIZE:]

        distance, stable_rssi = robust_distance_from_rssi(rssi_history, measure_power)

        confidence = compute_confidence(
            rssi=rssi,
            sightings=sightings,
            avg_rssi=avg_rssi,
            jitter=jitter,
            age_seconds=now - first_seen,
        )

        detected_devices[bssid] = {
            "bssid": bssid,
            "ssid": ssid,
            "rssi": rssi,
            "avg_rssi": round(avg_rssi, 2),
            "rssi_jitter": round(jitter, 2),
            "rssi_stable": stable_rssi,
            "rssi_history": rssi_history,
            "sightings": sightings,
            "first_seen": first_seen,
            "distance": distance,
            "risk": risk,
            "category": category,
            "matches": matches,
            "confidence": confidence,
            "crypto": crypto,
            "channel": channel,
            "last_seen": now,
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
    index = 0

    while not stop_event.is_set():
        with device_lock:
            enabled = bool(CHANNEL_STATE.get("enabled", True))
            mode = str(CHANNEL_STATE.get("mode", "2.4GHz"))
            locked_channel = CHANNEL_STATE.get("locked_channel")
            dynamic_hop_delay = float(CHANNEL_STATE.get("hop_delay", hop_delay))

        if not enabled:
            time.sleep(0.25)
            continue

        channels = CHANNEL_LISTS.get(mode, CHANNEL_LISTS["2.4GHz"])
        if locked_channel is not None:
            channel = int(locked_channel)
            sleep_time = 0.5
        else:
            channel = int(channels[index % len(channels)])
            index += 1
            sleep_time = max(0.12, min(dynamic_hop_delay, 2.0))

        subprocess.run(
            ["iw", "dev", interface_name, "set", "channel", str(channel)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        with device_lock:
            CHANNEL_STATE["current_channel"] = channel
        time.sleep(sleep_time)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/networks")
def api_networks():
    with device_lock:
        channel_state = dict(CHANNEL_STATE)
    return jsonify({
        "count": len(detected_devices),
        "networks": build_radar_payload(),
        "channel": channel_state,
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

    with device_lock:
        channel_state = dict(CHANNEL_STATE)

    return jsonify({
        "count": len(detected_devices),
        "networks": build_radar_payload(),
        "channel": channel_state,
        "version": current_version,
        "timestamp": time.time(),
    })


@app.route("/api/channel", methods=["GET", "POST"])
def api_channel():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        with device_lock:
            mode = payload.get("mode")
            if mode in CHANNEL_LISTS:
                CHANNEL_STATE["mode"] = mode

            if "enabled" in payload:
                CHANNEL_STATE["enabled"] = bool(payload.get("enabled"))

            if "hop_delay" in payload:
                try:
                    delay = float(payload.get("hop_delay"))
                    CHANNEL_STATE["hop_delay"] = max(0.12, min(delay, 2.0))
                except (TypeError, ValueError):
                    pass

            if "locked_channel" in payload:
                value = payload.get("locked_channel")
                if value in [None, "", 0, "0"]:
                    CHANNEL_STATE["locked_channel"] = None
                else:
                    try:
                        CHANNEL_STATE["locked_channel"] = int(value)
                    except (TypeError, ValueError):
                        pass

    with device_lock:
        return jsonify(dict(CHANNEL_STATE))


@app.route("/api/movement", methods=["GET", "POST"])
def api_movement():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        if payload.get("clear"):
            with device_lock:
                movement_points.clear()
            return jsonify({"ok": True, "cleared": True})

        lat = payload.get("lat")
        lon = payload.get("lon")
        top_bssid = payload.get("top_bssid")
        top_ssid = payload.get("top_ssid")
        top_rssi = payload.get("top_rssi")

        try:
            lat = float(lat)
            lon = float(lon)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "invalid lat/lon"}), 400

        point = {
            "ts": time.time(),
            "lat": lat,
            "lon": lon,
            "top_bssid": top_bssid,
            "top_ssid": top_ssid,
            "top_rssi": top_rssi,
        }

        with device_lock:
            movement_points.append(point)
            if len(movement_points) > 500:
                del movement_points[0 : len(movement_points) - 500]
        return jsonify({"ok": True})

    with device_lock:
        points = list(movement_points)
    return jsonify({"count": len(points), "points": points})


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