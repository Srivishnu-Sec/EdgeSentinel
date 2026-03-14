from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import subprocess
import json
import sys
import os

sys.path.insert(0, '/home/owner/edgesentinel/forensics')
sys.path.insert(0, '/home/owner/edgesentinel/gateway')

import risk_engine as re
import forensic_chain as fc

app = Flask(__name__)
app.config['SECRET_KEY'] = 'edgesentinel_secret'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Device Registration ──────────────────────────────────────────

@app.route('/api/devices/register', methods=['POST'])
def register_device():
    data = request.json
    device_id = data.get('device_id')
    has_hsm = data.get('has_hsm', False)

    device = re.register_device(device_id, has_hsm)
    fc.add_event(device_id, 'DEVICE_REGISTERED',
                 f'Device registered. HSM: {has_hsm}', risk_score=0)

    socketio.emit('device_update', re.get_all_devices())
    return jsonify({"status": "registered", "device": device})

# ── Risk Score ───────────────────────────────────────────────────

@app.route('/api/devices/<device_id>/status', methods=['GET'])
def device_status(device_id):
    status = re.get_device_status(device_id)
    if not status:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(status)

@app.route('/api/devices', methods=['GET'])
def all_devices():
    return jsonify(re.get_all_devices())

@app.route('/api/devices/<device_id>/signal', methods=['POST'])
def fire_signal(device_id):
    data = request.json
    signal = data.get('signal')

    re.fire_signal(device_id, signal)
    device = re.get_device_status(device_id)

    fc.add_event(device_id, f'SIGNAL_{signal.upper()}',
                 f'Signal {signal} fired',
                 risk_score=device['risk_score'])

    socketio.emit('device_update', re.get_all_devices())
    return jsonify({"status": "signal fired", "device": device})

# ── OPA Policy Check ─────────────────────────────────────────────

@app.route('/api/policy/check', methods=['POST'])
def policy_check():
    data = request.json
    device_id = data.get('device_id')
    action = data.get('action')

    input_data = json.dumps({"device_id": device_id, "action": action})

    result = subprocess.run(
        ['opa', 'eval', '-d',
         '/home/owner/edgesentinel/policies/device_policy.rego',
         '-I', 'data.edgesentinel.devices.allow'],
        input=input_data,
        capture_output=True, text=True
    )

    output = json.loads(result.stdout)
    allowed = output['result'][0]['expressions'][0]['value']

    if not allowed:
        re.fire_signal(device_id, 'opa_violation')
        device = re.get_device_status(device_id)
        fc.add_event(device_id, 'OPA_VIOLATION',
                     f'Action {action} denied by policy',
                     risk_score=device['risk_score'] if device else 0)
        socketio.emit('device_update', re.get_all_devices())

    return jsonify({"allowed": allowed, "device_id": device_id, "action": action})

# ── Forensic Chain ───────────────────────────────────────────────

@app.route('/api/forensics', methods=['GET'])
def get_forensics():
    chain = fc.load_chain()
    return jsonify(chain)

@app.route('/api/forensics/verify', methods=['GET'])
def verify_forensics():
    result = fc.verify_chain()
    return jsonify({"intact": result})

# ── WireGuard Control ────────────────────────────────────────────

@app.route('/api/wireguard/delete/<device_id>', methods=['POST'])
def delete_peer(device_id):
    peer_keys = {
        "pizero": "6gAcRp1qk0HfVtQtQVOpjRkG81+Bs9kajNYnT0Mx5HU=",
        "esp32_1": "o1zHg+VfJgnK5LorYqU2zDmOpqJZMaoEaaoVKguj7QY="
    }

    if device_id not in peer_keys:
        return jsonify({"error": "Device not found"}), 404

    pubkey = peer_keys[device_id]
    subprocess.run(['sudo', 'wg', 'set', 'wg0', 'peer', pubkey, 'remove'])

    fc.add_event(device_id, 'WIREGUARD_PEER_DELETED',
                 'WireGuard peer deleted — device quarantined', risk_score=0)

    socketio.emit('device_update', re.get_all_devices())
    return jsonify({"status": "peer deleted", "device_id": device_id})

# ── Dashboard SocketIO ───────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    emit('device_update', re.get_all_devices())
    print("[SOCKET] Dashboard connected")

# ── Run ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Register devices on startup
    re.register_device('pizero', has_hsm=False)
    re.register_device('esp32_1', has_hsm=True)
    re.register_device('esp32_rogue', has_hsm=False)

    print("[EDGESENTINEL] Gateway API starting on port 5000...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
