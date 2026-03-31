import sys
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

sys.path.insert(0, '/home/owner/edgesentinel/gateway')
sys.path.insert(0, '/home/owner/edgesentinel/forensics')

import risk_engine as re
import forensic_chain as fc

try:
    from ml_monitor import update_traffic
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

# ── Configuration ────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 5      # unique ports in time window = port scan
FLOOD_THRESHOLD = 50         # packets per second = flood
TIME_WINDOW = 10             # seconds to track behaviour

# ── Device IP mapping ────────────────────────────────────────────
IP_TO_DEVICE = {
    "10.0.0.2": "pizero",
    "10.0.0.3": "esp32_1"
}

# ── Tracking state ───────────────────────────────────────────────
port_tracker = defaultdict(set)        # device -> set of ports contacted
packet_tracker = defaultdict(deque)    # device -> timestamps of packets
alerted_devices = set()               # devices already alerted

def get_device_id(ip):
    """Map IP to device ID."""
    return IP_TO_DEVICE.get(ip, f"unknown_{ip}")

def detect_port_scan(device_id, dst_port):
    """Detect if device is scanning ports."""
    port_tracker[device_id].add(dst_port)
    unique_ports = len(port_tracker[device_id])

    if unique_ports >= PORT_SCAN_THRESHOLD:
        if device_id not in alerted_devices:
            alerted_devices.add(device_id)
            print(f"[SCAPY] PORT SCAN detected from {device_id} — {unique_ports} unique ports")
            re.fire_signal(device_id, 'scapy_anomaly')
            fc.add_event(
                device_id,
                'PORT_SCAN_DETECTED',
                f'Port scan detected — {unique_ports} unique ports contacted',
                risk_score=re.get_device_status(device_id)['risk_score']
                if re.get_device_status(device_id) else 0
            )
            # Reset after alert
            port_tracker[device_id] = set()

def detect_flood(device_id):
    # Feed into ML monitor
    if ML_AVAILABLE:
        proto = 6 if TCP in packet else 17 if UDP in packet else 0
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        update_traffic(device_id, len(packet), port, proto)
    """Detect if device is flooding the network."""
    now = time.time()
    packet_tracker[device_id].append(now)

    # Remove packets outside time window
    while packet_tracker[device_id] and \
          packet_tracker[device_id][0] < now - TIME_WINDOW:
        packet_tracker[device_id].popleft()

    pps = len(packet_tracker[device_id]) / TIME_WINDOW

    if pps >= FLOOD_THRESHOLD:
        if f"flood_{device_id}" not in alerted_devices:
            alerted_devices.add(f"flood_{device_id}")
            print(f"[SCAPY] FLOOD detected from {device_id} — {pps:.1f} packets/sec")
            re.fire_signal(device_id, 'scapy_anomaly')
            fc.add_event(
                device_id,
                'FLOOD_DETECTED',
                f'Traffic flood detected — {pps:.1f} packets/sec',
                risk_score=re.get_device_status(device_id)['risk_score']
                if re.get_device_status(device_id) else 0
            )

def packet_callback(packet):
    """Process each captured packet."""
    if IP not in packet:
        return

    src_ip = packet[IP].src
    device_id = get_device_id(src_ip)

    # Only monitor our known devices
    if not src_ip.startswith("10.0.0."):
        return

    # Skip gateway itself
    if src_ip == "10.0.0.1":
        return

    # Detect flood
    detect_flood(device_id)

    # Detect port scan on TCP/UDP
    if TCP in packet:
        detect_port_scan(device_id, packet[TCP].dport)
    elif UDP in packet:
        detect_port_scan(device_id, packet[UDP].dport)

    print(f"[PACKET] {device_id} ({src_ip}) → {packet[IP].dst}")

def reset_alerts():
    """Reset alert state every TIME_WINDOW seconds."""
    while True:
        time.sleep(TIME_WINDOW)
        alerted_devices.clear()
        port_tracker.clear()
        print(f"[SCAPY] Alert state reset at {datetime.now().strftime('%H:%M:%S')}")

def start_monitor(interface="wg0"):
    """Start the packet monitor."""
    print(f"[SCAPY] Starting monitor on interface: {interface}")
    print(f"[SCAPY] Port scan threshold: {PORT_SCAN_THRESHOLD} unique ports")
    print(f"[SCAPY] Flood threshold: {FLOOD_THRESHOLD} packets/sec")

    # Start reset thread
    reset_thread = threading.Thread(target=reset_alerts, daemon=True)
    reset_thread.start()

    # Start sniffing
    sniff(
        iface=interface,
        prn=packet_callback,
        store=False,
        filter="ip"
    )

if __name__ == '__main__':
    # Register devices first
    re.register_device('pizero', has_hsm=False)
    re.register_device('esp32_1', has_hsm=True)
    re.register_device('esp32_rogue', has_hsm=False)

    start_monitor(interface="wg0")
