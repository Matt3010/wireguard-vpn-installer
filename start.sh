#!/bin/bash

# 1. Avvia il tuo script Python in background
echo "[CUSTOM-INIT] Starting Firewall Manager (main.py)..."
python3 /app/main.py &

# 2. Passa il controllo all'entrypoint originale di wg-easy
# Questo avvia WireGuard e la Web UI
echo "[CUSTOM-INIT] Starting WG-Easy..."
exec /usr/bin/dumb-init node server.js