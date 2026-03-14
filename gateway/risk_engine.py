import json
import time
from datetime import datetime

# Anomaly threshold from TinyML model
ANOMALY_THRESHOLD = 0.002005

# Risk score weights
WEIGHTS = {
    "no_hsm": 40,
    "tinyml_anomaly": 30,
    "scapy_anomaly": 20,
    "opa_violation": 10
}

# Response tiers
TIERS = {
    "TRUSTED": (0, 30),
    "SUSPICIOUS": (31, 60),
    "QUARANTINE": (61, 80),
    "BLACKLIST": (81, 100)
}

# Device registry — stores live state of each device
devices = {}

def register_device(device_id, has_hsm=True):
    """Register a new device with default state."""
    devices[device_id] = {
        "device_id": device_id,
        "has_hsm": has_hsm,
        "risk_score": 0,
        "tier": "TRUSTED",
        "signals": {
            "no_hsm": False,
            "tinyml_anomaly": False,
            "scapy_anomaly": False,
            "opa_violation": False
        },
        "last_updated": datetime.now().isoformat(),
        "quarantined": False,
        "blacklisted": False
    }
    print(f"[REGISTER] Device {device_id} registered. HSM: {has_hsm}")
    return devices[device_id]

def calculate_risk_score(device_id):
    """Calculate risk score from active signals."""
    if device_id not in devices:
        print(f"[ERROR] Device {device_id} not found.")
        return None

    device = devices[device_id]
    score = 0

    for signal, active in device["signals"].items():
        if active:
            score += WEIGHTS[signal]

    # Cap at 100
    score = min(score, 100)
    device["risk_score"] = score
    device["last_updated"] = datetime.now().isoformat()

    # Determine tier
    for tier, (low, high) in TIERS.items():
        if low <= score <= high:
            device["tier"] = tier
            break

    return score

def fire_signal(device_id, signal):
    """Fire a risk signal for a device."""
    if device_id not in devices:
        print(f"[ERROR] Device {device_id} not found.")
        return

    if signal not in WEIGHTS:
        print(f"[ERROR] Unknown signal: {signal}")
        return

    devices[device_id]["signals"][signal] = True
    score = calculate_risk_score(device_id)
    tier = devices[device_id]["tier"]

    print(f"[SIGNAL] {device_id} | Signal: {signal} | Score: {score} | Tier: {tier}")

    # Trigger response
    handle_response(device_id, score, tier)

def clear_signal(device_id, signal):
    """Clear a risk signal for a device."""
    if device_id not in devices:
        return
    devices[device_id]["signals"][signal] = False
    calculate_risk_score(device_id)

def handle_response(device_id, score, tier):
    """Automatically respond based on risk tier."""
    device = devices[device_id]

    if tier == "TRUSTED":
        print(f"[TRUSTED] {device_id} — Normal operation.")

    elif tier == "SUSPICIOUS":
        print(f"[SUSPICIOUS] {device_id} — Rate limiting applied.")

    elif tier == "QUARANTINE":
        if not device["quarantined"]:
            device["quarantined"] = True
            print(f"[QUARANTINE] {device_id} — WireGuard peer deleted. Device isolated.")
            # WireGuard deletion will be called here in Phase 4

    elif tier == "BLACKLIST":
        if not device["blacklisted"]:
            device["blacklisted"] = True
            device["quarantined"] = True
            print(f"[BLACKLIST] {device_id} — Certificate revoked. Permanent block.")

def get_device_status(device_id):
    """Return current status of a device."""
    if device_id not in devices:
        return None
    return devices[device_id]

def get_all_devices():
    """Return status of all devices."""
    return devices
