# EdgeSentinel
### Zero-Trust IoT Security Gateway with Hardware Root of Trust & Edge Intelligence

![Status](https://img.shields.io/badge/Status-Active-00FF88)
![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi%20%7C%20ESP32-00D4FF)
![Security](https://img.shields.io/badge/Security-Zero%20Trust-FF4444)

## What is EdgeSentinel?

EdgeSentinel is a hardware-backed, autonomous IoT security gateway that enforces Zero-Trust principles at the network edge. It assumes no device is trustworthy by default — even devices already connected. Every packet, every command, every connection is verified, scored, and logged in real time.

## Architecture — 6 Security Layers

| Layer | Component | Function |
|-------|-----------|----------|
| L1 | TinyML Autoencoder (ESP32) | On-device anomaly detection |
| L2 | ATECC608A Chip | Hardware-rooted device identity |
| L3 | WireGuard VPN | Encrypted network tunnel |
| L4 | Python Scapy | Packet-level behaviour monitoring |
| L5 | Open Policy Agent | Role-based access control |
| L6 | SHA-256 + RFC 3161 | Tamper-evident forensic chain |

## Risk Score Engine

Each device carries a live risk score (0–100) calculated from 4 signals:

- No HSM / invalid signature → +40 points
- TinyML anomaly score → +30 points  
- Packet behaviour anomaly → +20 points
- OPA policy violation → +10 points

| Score | Tier | Action |
|-------|------|--------|
| 0–30 | TRUSTED | Normal operation |
| 31–60 | SUSPICIOUS | Rate limiting |
| 61–80 | QUARANTINE | WireGuard peer deleted |
| 81–100 | BLACKLIST | Certificate revoked |

## Hardware

- Raspberry Pi Zero 2W — Legitimate Device #1
- ESP32 DevKit V1 × 2 — Legitimate Device #2 + Rogue Device
- ATECC608A Breakout Board — Hardware Root of Trust
- DHT11 Sensors × 2 — Temperature/humidity data

## Tech Stack

- **Gateway:** Python, WireGuard, Mosquitto MQTT, OPA, Scapy, Flask, Flask-SocketIO
- **ML:** TensorFlow Lite Micro, N-BaIoT dataset, Autoencoder
- **Dashboard:** React, Three.js, Socket.io
- **Forensics:** SHA-256 hash chain, RFC 3161 timestamps via FreeTSA.org

## Research Gaps Addressed

1. Absence of hardware-software co-designed IoT security systems
2. No on-device AI inference on constrained edge hardware
3. Lack of real hardware validation in zero-trust IoT prototypes

## Quick Start
```bash
# Start gateway
bash ~/edgesentinel/start.sh

# Start dashboard
cd edgesentinel-dashboard && npm start
```

## Live Demo Scenarios

1. Normal operation — all devices green, data flowing
2. Rogue device blocked — no HSM, WireGuard rejects instantly
3. Port scan detected — Scapy fires, node turns yellow
4. Replay attack + auto quarantine — risk crosses 61, red in under 2 seconds
5. Forensic chain tamper demo — edit one character, verifier catches it instantly

## Team

Built for national hackathon — Team of 3
