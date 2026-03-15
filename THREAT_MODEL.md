# EdgeSentinel Threat Model

## System Overview

EdgeSentinel is a Zero-Trust IoT security gateway protecting a network of ESP32 and Raspberry Pi devices. This document describes the threat landscape, attack vectors, and how each layer of EdgeSentinel defends against them.

---

## Assets Being Protected

| Asset | Description |
|-------|-------------|
| IoT Devices | ESP32 sensors, Raspberry Pi Zero 2W |
| Sensor Data | Temperature, humidity readings |
| Network | WireGuard VPN tunnel |
| Gateway | Raspberry Pi / Laptop running all engines |
| Forensic Chain | Tamper-evident audit log |
| Certificates | Device identity credentials |

---

## Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| External Attacker | Network access, packet injection | Disrupt sensors, steal data |
| Rogue Device | Valid network position | Impersonate legitimate device |
| Compromised Device | Legitimate credentials | Lateral movement, policy abuse |
| Insider Threat | Physical access | Tamper with devices or logs |

---

## Attack Vectors & Defences

### 1. Rogue Device Joining Network
**Attack:** Attacker connects unauthorised device to the network.
**Defence:** WireGuard rejects any device without a valid cryptographic key. No key = no network access. Risk score fires +40 for missing HSM.

### 2. Device Identity Spoofing
**Attack:** Attacker clones a legitimate device's software identity (JWT, certificate).
**Defence:** ATECC608A chip stores private key in hardware. Key cannot be extracted, copied, or cloned. Software identity can be faked — hardware identity cannot.

### 3. Replay Attack
**Attack:** Attacker captures legitimate packets and replays them to impersonate a device.
**Defence:** Each message is signed with a timestamp by the ATECC608A chip. Replayed packets have stale timestamps and fail signature verification. Risk score escalates to QUARANTINE.

### 4. Port Scan / Network Reconnaissance
**Attack:** Compromised device scans the network to map services and find vulnerabilities.
**Defence:** Scapy monitor detects 5+ unique port contacts within 10 seconds. Fires scapy_anomaly signal immediately. Device moves to SUSPICIOUS tier.

### 5. Traffic Flood / DoS
**Attack:** Compromised device floods the gateway with packets to disrupt service.
**Defence:** Scapy monitor tracks packets per second. Exceeding 50 packets/second triggers flood detection. Device rate limited and flagged.

### 6. Privilege Escalation via MQTT
**Attack:** Compromised temperature sensor sends unauthorised commands (shutdown, firmware update).
**Defence:** OPA policy engine enforces strict role-based access. Temperature sensor role cannot send shutdown commands regardless of how the device is compromised. Violation fires opa_violation signal.

### 7. Forensic Log Tampering
**Attack:** Attacker modifies audit logs to cover tracks after an intrusion.
**Defence:** SHA-256 hash chain links every event to the previous one. Modifying any event breaks all subsequent hashes. RFC 3161 timestamps provide external verification anchor.

### 8. Man-in-the-Middle Attack
**Attack:** Attacker intercepts traffic between devices and gateway.
**Defence:** All traffic travels through WireGuard VPN tunnel with end-to-end encryption. Intercepted packets are unreadable without the device's private key.

### 9. Physical Device Tampering
**Attack:** Attacker gains physical access to ESP32 and attempts to extract private key.
**Defence:** ATECC608A secure enclave makes private key physically unextractable. Even with full physical access, the key cannot be retrieved.

### 10. Slow Exfiltration Attack
**Attack:** Attacker exfiltrates data slowly to avoid detection thresholds.
**Defence:** Known limitation. TinyML autoencoder monitors traffic patterns — slow exfiltration mimicking normal behaviour may evade detection. Documented as v2 improvement.

---

## Risk Score Trigger Matrix

| Attack | no_hsm | tinyml | scapy | opa | Max Score | Response |
|--------|--------|--------|-------|-----|-----------|----------|
| Rogue device | ✓ | | | | 40 | SUSPICIOUS |
| Port scan | | | ✓ | | 20 | TRUSTED→SUSPICIOUS |
| Replay attack | ✓ | ✓ | | | 70 | QUARANTINE |
| Policy abuse | | | | ✓ | 10 | TRUSTED |
| Full compromise | ✓ | ✓ | ✓ | ✓ | 100 | BLACKLIST |

---

## Trust Boundaries
```
[ Physical World ]
      ↓
[ ESP32 / Pi Zero ] — ATECC608A hardware identity
      ↓
[ WireGuard Tunnel ] — encrypted, authenticated
      ↓
[ Gateway ] — Scapy + OPA + Risk Engine
      ↓
[ Dashboard ] — read-only display
      ↓
[ Forensic Chain ] — append-only, tamper-evident
```

---

## Known Limitations

1. ML model trained on synthetic data — real-world retraining needed for production
2. Single gateway — no redundancy in current v1
3. Static OPA policies — dynamic policy generation is v2 scope
4. No OTA firmware updates — devices must be manually reflashed
5. Slow exfiltration attacks may evade TinyML detection threshold

---

## v2 Roadmap

- Distributed CA with intermediate certificate authorities per zone
- Multiple gateway instances with shared trust model
- Dynamic OPA policy generation based on device behaviour
- Secure OTA firmware update mechanism
- Real-world N-BaIoT retraining pipeline
