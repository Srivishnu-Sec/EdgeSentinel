#!/usr/bin/env python3
import sys
import time
import threading
import requests
import argparse

GATEWAY_URL = "http://192.168.43.209:5000"

DEVICES = ["pizero", "esp32_1", "esp32_rogue"]

def print_banner():
    print("""
╔══════════════════════════════════════════╗
║     EDGESENTINEL ATTACK SIMULATOR        ║
║     Compromise any device on command     ║
╚══════════════════════════════════════════╝
    """)

def fire_signal(device_id, signal):
    for attempt in range(3):
        try:
            res = requests.post(
                f"{GATEWAY_URL}/api/devices/{device_id}/signal",
                json={"signal": signal},
                timeout=15
            )
            data = res.json()
            score = data.get('device', {}).get('risk_score', '?')
            tier  = data.get('device', {}).get('tier', '?')
            print(f"  [SIGNAL] {signal} → Score: {score} | Tier: {tier}")
            return
        except Exception as e:
            print(f"  [RETRY {attempt+1}] {signal} failed — retrying...")
            time.sleep(3)
    print(f"  [FAILED] {signal} could not be sent after 3 attempts")

def attack_device(device_id, mode="full"):
    print(f"\n[ATTACK] Compromising {device_id} — mode: {mode}")
    print(f"[ATTACK] Gateway will detect and respond autonomously\n")

    if mode == "rogue" or mode == "full":
        print("[STAGE 1] Rogue identity detected — no HSM chip")
        fire_signal(device_id, "no_hsm")
        time.sleep(5)

    if mode == "scan" or mode == "full":
        print("[STAGE 2] Port scan detected by Scapy monitor")
        fire_signal(device_id, "scapy_anomaly")
        time.sleep(5)

    if mode == "ml" or mode == "full":
        print("[STAGE 3] ML anomaly detected — abnormal traffic pattern")
        fire_signal(device_id, "tinyml_anomaly")
        time.sleep(5)

    if mode == "policy" or mode == "full":
        print("[STAGE 4] OPA policy violation — unauthorized command sent")
        fire_signal(device_id, "opa_violation")
        time.sleep(4)

    print(f"\n[RESULT] {device_id} has been compromised and quarantined.")
    print("[RESULT] Check the dashboard — device should be BLACKLISTED.\n")

def reset_all():
    try:
        requests.post(f"{GATEWAY_URL}/api/reset", timeout=15)
        print("[RESET] All devices cleared — system back to clean state.")
    except Exception as e:
        print(f"[ERROR] Reset failed: {e}")

def interactive_mode():
    print_banner()
    while True:
        print("Available devices:")
        for i, d in enumerate(DEVICES):
            print(f"  {i+1}. {d}")
        print("  4. RESET all devices")
        print("  5. Exit")
        print()
        choice = input("Select device to compromise (1-3) or action (4-5): ").strip()

        if choice == "4":
            reset_all()
        elif choice == "5":
            print("Exiting.")
            break
        elif choice in ["1", "2", "3"]:
            device = DEVICES[int(choice) - 1]
            print()
            print("Attack mode:")
            print("  1. Full attack (all 4 stages)")
            print("  2. Rogue identity only")
            print("  3. Port scan only")
            print("  4. ML anomaly only")
            print("  5. Policy violation only")
            mode_choice = input("Select mode (1-5): ").strip()
            modes = {"1": "full", "2": "rogue", "3": "scan", "4": "ml", "5": "policy"}
            mode = modes.get(mode_choice, "full")
            attack_device(device, mode)
        else:
            print("Invalid choice. Try again.\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EdgeSentinel Attack Simulator')
    parser.add_argument('--target', choices=DEVICES, help='Device to compromise')
    parser.add_argument('--mode', default='full',
                        choices=['full','rogue','scan','ml','policy'],
                        help='Attack mode')
    parser.add_argument('--reset', action='store_true', help='Reset all devices')
    args = parser.parse_args()

    print_banner()

    if args.reset:
        reset_all()
    elif args.target:
        attack_device(args.target, args.mode)
    else:
        interactive_mode()
