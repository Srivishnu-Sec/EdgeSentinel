#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
from datetime import datetime

CERTS_DIR = "/home/owner/edgesentinel/certs"
WG_CONFIG = "/etc/wireguard/wg0.conf"

# IP assignments for new devices
IP_POOL = {
    "pizero": "10.0.0.2",
    "esp32_1": "10.0.0.3",
    "esp32_2": "10.0.0.4",
    "esp32_3": "10.0.0.5",
}

def print_banner():
    print("""
╔══════════════════════════════════════════╗
║     EDGESENTINEL DEVICE ONBOARDER        ║
║     Zero-Trust Device Registration       ║
╚══════════════════════════════════════════╝
    """)

def generate_certificate(device_id):
    """Generate private key and certificate for device."""
    print(f"[CERT] Generating certificate for {device_id}...")

    key_file = f"{CERTS_DIR}/{device_id}.key"
    csr_file = f"{CERTS_DIR}/{device_id}.csr"
    crt_file = f"{CERTS_DIR}/{device_id}.crt"

    # Generate private key
    subprocess.run([
        "openssl", "genrsa", "-out", key_file, "2048"
    ], capture_output=True)

    # Generate CSR
    subprocess.run([
        "openssl", "req", "-new", "-key", key_file,
        "-out", csr_file,
        "-subj", f"/C=IN/ST=TamilNadu/L=Chennai/O=EdgeSentinel/OU=Devices/CN={device_id}"
    ], capture_output=True)

    # Sign certificate with CA
    subprocess.run([
        "openssl", "x509", "-req", "-days", "365",
        "-in", csr_file,
        "-CA", f"{CERTS_DIR}/ca.crt",
        "-CAkey", f"{CERTS_DIR}/ca.key",
        "-CAcreateserial",
        "-out", crt_file
    ], capture_output=True)

    print(f"[CERT] ✓ Certificate generated: {crt_file}")
    return key_file, crt_file

def generate_wireguard_keys(device_id):
    """Generate WireGuard key pair for device."""
    print(f"[WG] Generating WireGuard keys for {device_id}...")

    key_file = f"{CERTS_DIR}/{device_id}_wg.key"
    pub_file = f"{CERTS_DIR}/{device_id}_wg.pub"

    result = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
    private_key = result.stdout.strip()

    with open(key_file, 'w') as f:
        f.write(private_key)

    result = subprocess.run(["wg", "pubkey"], input=private_key,
                          capture_output=True, text=True)
    public_key = result.stdout.strip()

    with open(pub_file, 'w') as f:
        f.write(public_key)

    print(f"[WG] ✓ WireGuard keys generated")
    return private_key, public_key

def add_wireguard_peer(device_id, public_key):
    """Add device as WireGuard peer."""
    ip = IP_POOL.get(device_id)
    if not ip:
        print(f"[WG] ERROR: No IP assigned for {device_id}")
        return False

    print(f"[WG] Adding WireGuard peer {device_id} at {ip}...")

    result = subprocess.run([
        "sudo", "wg", "set", "wg0",
        "peer", public_key,
        "allowed-ips", f"{ip}/32"
    ], capture_output=True)

    if result.returncode == 0:
        print(f"[WG] ✓ Peer added at {ip}")
        return True
    else:
        print(f"[WG] ERROR: {result.stderr.decode()}")
        return False

def print_device_config(device_id, private_key, public_key):
    """Print WireGuard config for the device to use."""
    ip = IP_POOL.get(device_id, "10.0.0.x")

    # Get gateway public key
    with open(f"{CERTS_DIR}/gateway.pub", 'r') as f:
        gateway_pub = f.read().strip()

    print(f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DEVICE CONFIG FOR: {device_id}
  Copy this to your device
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Interface]
PrivateKey = {private_key}
Address = {ip}/24

[Peer]
PublicKey = {gateway_pub}
Endpoint = GATEWAY_IP:51820
AllowedIPs = 10.0.0.0/24

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Device IP: {ip}
  Certificate: {CERTS_DIR}/{device_id}.crt
  Key: {CERTS_DIR}/{device_id}.key
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)

def onboard_device(device_id, has_hsm=False):
    """Full onboarding flow for a new device."""
    print_banner()
    print(f"Onboarding device: {device_id}")
    print(f"HSM chip present: {has_hsm}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()

    # Step 1 — Generate certificate
    key_file, crt_file = generate_certificate(device_id)

    # Step 2 — Generate WireGuard keys
    private_key, public_key = generate_wireguard_keys(device_id)

    # Step 3 — Add WireGuard peer
    add_wireguard_peer(device_id, public_key)

    # Step 4 — Print device config
    print_device_config(device_id, private_key, public_key)

    print(f"✓ Device {device_id} onboarded successfully.")
    print(f"  HSM: {'YES — Hardware Root of Trust active' if has_hsm else 'NO — Software certificate only'}")
    print()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EdgeSentinel Device Onboarder')
    parser.add_argument('--device', required=True, help='Device ID (e.g. esp32_1)')
    parser.add_argument('--hsm', action='store_true', help='Device has ATECC608A chip')
    args = parser.parse_args()

    onboard_device(args.device, args.hsm)
