from flask import Flask, jsonify, request
from datetime import datetime
from flask_socketio import SocketIO, emit
from flask import current_app
from flask_cors import CORS
import subprocess
import json
import sys
import os
import paho.mqtt.client as mqtt_client

sys.path.insert(0, '/home/owner/edgesentinel/forensics')
sys.path.insert(0, '/home/owner/edgesentinel/gateway')

import risk_engine as re
import forensic_chain as fc

app = Flask(__name__)
app.config["SECRET_KEY"] = "edgesentinel_secret"
CORS(app, origins="*")

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
# ── Sensor Data ──────────────────────────────────────────────────
sensor_data = {
    "pizero": {"temperature": None, "humidity": None, "last_updated": None},
    "esp32_1": {"temperature": None, "humidity": None, "last_updated": None}
}

@app.route('/api/sensors', methods=['GET'])
def get_sensors():
    return jsonify(sensor_data)

@app.route('/api/sensors/<device_id>', methods=['POST'])
def update_sensor(device_id):
    data = request.json
    if device_id in sensor_data:
        sensor_data[device_id]['temperature'] = data.get('temperature')
        sensor_data[device_id]['humidity'] = data.get('humidity')
        sensor_data[device_id]['last_updated'] = datetime.now().isoformat()
        socketio.emit('sensor_update', sensor_data)
    return jsonify({"status": "updated"})
# ── Dashboard SocketIO ───────────────────────────────────────────
@app.route('/api/reset', methods=['POST'])
def reset_all():
    re.devices.clear()
    re.register_device('pizero', has_hsm=False)
    re.register_device('esp32_1', has_hsm=True)
    re.register_device('esp32_rogue', has_hsm=False)

    import json
    with open('/home/owner/edgesentinel/forensics/chain.json', 'w') as f:
        json.dump([], f)

    socketio.emit('device_update', re.get_all_devices())
    print("[RESET] All devices and forensic chain reset.")
    return jsonify({"status": "reset complete"})

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@socketio.on("connect")
def handle_connect():
    emit('device_update', re.get_all_devices())
    print("[SOCKET] Dashboard connected")

# ── Run ──────────────────────────────────────────────────────────
def on_mqtt_message(client, userdata, message):
    import json
    try:
        payload = json.loads(message.payload.decode())
        device_id = payload.get('device_id')
        temperature = payload.get('temperature')
        humidity = payload.get('humidity')
        if device_id and device_id in sensor_data:
            sensor_data[device_id]['temperature'] = temperature
            sensor_data[device_id]['humidity'] = humidity
            sensor_data[device_id]['last_updated'] = datetime.now().isoformat()
            socketio.emit('sensor_update', sensor_data)
            print(f"[MQTT] {device_id} -> Temp: {temperature}C | Humidity: {humidity}%")
    except Exception as e:
        print(f"[MQTT] Error: {e}")

def start_mqtt_subscriber():
    import threading
    def run():
        def on_connect(client, userdata, flags, reason_code, properties):
            print(f"[MQTT] Subscriber connected, reason: {reason_code}")
            client.subscribe("devices/#")
            print("[MQTT] Subscribed to devices/#")

        def on_message(client, userdata, message):
            import json
            try:
                print(f"[MQTT] Raw message received on {message.topic}")
                payload = json.loads(message.payload.decode())
                device_id = payload.get('device_id')
                temperature = payload.get('temperature')
                humidity = payload.get('humidity')
                if device_id and device_id in sensor_data:
                    sensor_data[device_id]['temperature'] = temperature
                    sensor_data[device_id]['humidity'] = humidity
                    sensor_data[device_id]['last_updated'] = datetime.now().isoformat()
                    print(f"[MQTT] {device_id} -> Temp: {temperature}C | Humidity: {humidity}%")
            except Exception as e:
                print(f"[MQTT] Error: {e}")

        import uuid
        mc = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, client_id=f"gateway_sub_{uuid.uuid4().hex[:8]}")
        mc.username_pw_set("edgesentinel", "pi02w")
        mc.on_connect = on_connect
        mc.on_message = on_message
        mc.connect("192.168.43.209", 1883, 60)
        mc.loop_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    print("[MQTT] Subscriber started — listening for device data")

if __name__ == '__main__':
    # Register devices on startup
    start_mqtt_subscriber()
    from ml_monitor import start_ml_monitor
    start_ml_monitor()
    re.register_device('pizero', has_hsm=False)
    re.register_device('esp32_1', has_hsm=True)
    re.register_device('esp32_rogue', has_hsm=False)

    print("[EDGESENTINEL] Gateway API starting on port 5000...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

