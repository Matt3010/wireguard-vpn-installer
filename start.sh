#!/bin/bash
#
#echo "[CUSTOM-INIT] Starting Firewall Manager (main.py)..."
#python3 /etc/wireguard/scripts/main.py &

echo "[CUSTOM-INIT] Starting WG-Easy..."
exec /usr/bin/dumb-init node server/index.mjs