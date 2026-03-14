#!/bin/bash

echo "╔══════════════════════════════════════╗"
echo "║       EDGESENTINEL GATEWAY           ║"
echo "║   Zero-Trust IoT Security Gateway    ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Check WireGuard
echo "[1/4] Checking WireGuard..."
if sudo wg show wg0 > /dev/null 2>&1; then
    echo "      ✓ WireGuard already running"
else
    sudo wg-quick up wg0
    echo "      ✓ WireGuard started"
fi

# Check Mosquitto
echo "[2/4] Checking Mosquitto..."
if systemctl is-active --quiet mosquitto; then
    echo "      ✓ Mosquitto already running"
else
    sudo systemctl start mosquitto
    echo "      ✓ Mosquitto started"
fi

# Start Scapy monitor in background
echo "[3/4] Starting Scapy monitor..."
sudo python3 /home/owner/edgesentinel/gateway/scapy_monitor.py > /home/owner/edgesentinel/scapy.log 2>&1 &
SCAPY_PID=$!
echo "      ✓ Scapy monitor started (PID: $SCAPY_PID)"

# Start Flask API
echo "[4/4] Starting Flask API..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dashboard: http://localhost:3000"
echo "  API:       http://localhost:5000"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd /home/owner/edgesentinel/gateway && python3 app.py
