import sys
import time
import threading
import numpy as np
import pickle
import requests
from collections import defaultdict, deque

sys.path.insert(0, '/home/owner/edgesentinel/gateway')
sys.path.insert(0, '/home/owner/edgesentinel/forensics')

import risk_engine as re
import forensic_chain as fc

# Load model
print("[ML] Loading autoencoder model...")
model = None
try:
    import tensorflow as tf
    model = tf.keras.models.load_model('/home/owner/edgesentinel/gateway/edgesentinel_autoencoder.keras')
    print("[ML] Model loaded successfully")
except Exception as e:
    print(f"[ML] Model load error: {e}")

# Load scaler
print("[ML] Loading scaler...")
scaler = None
try:
    with open('/home/owner/edgesentinel/gateway/edgesentinel_scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    print("[ML] Scaler loaded successfully")
except Exception as e:
    print(f"[ML] Scaler load error: {e}")

# Load threshold
THRESHOLD = 0.002005
try:
    with open('/home/owner/edgesentinel/gateway/edgesentinel_threshold.txt', 'r') as f:
        THRESHOLD = float(f.read().strip())
    print(f"[ML] Threshold: {THRESHOLD}")
except Exception as e:
    print(f"[ML] Using default threshold: {THRESHOLD}")

traffic_stats = defaultdict(lambda: {
    'packet_count': 0,
    'byte_count': 0,
    'timestamps': deque(maxlen=100),
    'packet_sizes': deque(maxlen=100),
    'ports': deque(maxlen=100),
    'protocols': deque(maxlen=100),
})

IP_TO_DEVICE = {
    "10.0.0.2": "pizero",
    "10.0.0.3": "esp32_1",
}

alerted_devices = set()

def update_traffic(device_id, packet_size, port, protocol):
    stats = traffic_stats[device_id]
    now = time.time()
    stats['packet_count'] += 1
    stats['byte_count'] += packet_size
    stats['timestamps'].append(now)
    stats['packet_sizes'].append(packet_size)
    stats['ports'].append(port)
    stats['protocols'].append(protocol)

def extract_features(device_id):
    stats = traffic_stats[device_id]
    if len(stats['timestamps']) < 2:
        return None
    now = time.time()
    timestamps = list(stats['timestamps'])
    sizes = list(stats['packet_sizes'])
    windows = [100, 10, 1, 0.1, 0.01]
    features = []
    for window in windows:
        recent = [(t, s) for t, s in zip(timestamps, sizes) if now - t <= window]
        if len(recent) == 0:
            features.extend([0.0] * 23)
            continue
        recent_sizes = [s for _, s in recent]
        count = len(recent_sizes)
        mean_size = np.mean(recent_sizes)
        std_size = np.std(recent_sizes) if len(recent_sizes) > 1 else 0
        total_bytes = sum(recent_sizes)
        if len(recent) > 1:
            time_span = recent[-1][0] - recent[0][0]
            pkt_rate = count / max(time_span, 0.001)
        else:
            pkt_rate = 0
        if len(recent) > 1:
            iats = [recent[i][0] - recent[i-1][0] for i in range(1, len(recent))]
            mean_iat = np.mean(iats)
            std_iat = np.std(iats)
        else:
            mean_iat = 0
            std_iat = 0
        window_features = [
            count, mean_size, std_size, total_bytes, pkt_rate,
            mean_iat, std_iat,
            min(recent_sizes) if recent_sizes else 0,
            max(recent_sizes) if recent_sizes else 0,
            np.median(recent_sizes) if recent_sizes else 0,
            np.percentile(recent_sizes, 25) if len(recent_sizes) > 1 else 0,
            np.percentile(recent_sizes, 75) if len(recent_sizes) > 1 else 0,
            count / max(1, stats['packet_count']),
            total_bytes / max(1, stats['byte_count']),
            std_size / max(mean_size, 0.001),
            0, 0, 0, 0, 0, 0, 0, 0
        ]
        features.extend(window_features[:23])
    features = features[:115]
    while len(features) < 115:
        features.append(0.0)
    return np.array(features, dtype=np.float32)

def run_inference(device_id):
    if model is None or scaler is None:
        return
    features = extract_features(device_id)
    if features is None:
        return
    try:
        features_scaled = scaler.transform(features.reshape(1, -1))
        reconstruction = model.predict(features_scaled, verbose=0)
        mse = np.mean(np.power(features_scaled - reconstruction, 2))
        print(f"[ML] {device_id} error: {mse:.6f} threshold: {THRESHOLD:.6f}")
        if mse > THRESHOLD:
            if device_id not in alerted_devices:
                alerted_devices.add(device_id)
                print(f"[ML] ANOMALY DETECTED on {device_id}")
                try:
                    requests.post(
                        f"http://localhost:5000/api/devices/{device_id}/signal",
                        json={"signal": "tinyml_anomaly"},
                        timeout=3
                    )
                    print(f"[ML] tinyml_anomaly signal fired for {device_id}")
                except Exception as e:
                    print(f"[ML] API error: {e}")
                fc.add_event(device_id, 'ML_ANOMALY_DETECTED',
                    f'Reconstruction error: {mse:.6f} > threshold: {THRESHOLD:.6f}', risk_score=0)
        else:
            alerted_devices.discard(device_id)
    except Exception as e:
        print(f"[ML] Inference error: {e}")

def start_packet_monitor():
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except ImportError:
        print("[ML] Scapy not available")
        return
    def packet_callback(packet):
        if IP not in packet:
            return
        src_ip = packet[IP].src
        if not src_ip.startswith("10.0.0."):
            return
        if src_ip == "10.0.0.1":
            return
        device_id = IP_TO_DEVICE.get(src_ip, f"unknown_{src_ip}")
        size = len(packet)
        port = 0
        proto = 0
        if TCP in packet:
            port = packet[TCP].dport
            proto = 6
        elif UDP in packet:
            port = packet[UDP].dport
            proto = 17
        update_traffic(device_id, size, port, proto)
    print("[ML] Packet monitor starting on wg0...")
    sniff(iface="wg0", prn=packet_callback, store=False, filter="ip")

def inference_loop():
    while True:
        time.sleep(10)
        for device_id in list(traffic_stats.keys()):
            if traffic_stats[device_id]['packet_count'] > 5:
                run_inference(device_id)

def start_ml_monitor():
    if model is None or scaler is None:
        print("[ML] Model or scaler not loaded — ML monitor disabled")
        return
    inference_thread = threading.Thread(target=inference_loop, daemon=True)
    inference_thread.start()
    print("[ML] Autonomous ML monitor started")
    print(f"[ML] Threshold: {THRESHOLD}")

if __name__ == '__main__':
    re.register_device('pizero', has_hsm=False)
    re.register_device('esp32_1', has_hsm=True)
    start_ml_monitor()
    print("[ML] Running — press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[ML] Stopped")
