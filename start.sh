#!/bin/bash

ls -la /app/

echo "[CUSTOM-INIT] Starting Firewall Manager (main.py)..."
nohup python3 -u /app/main.py > /proc/1/fd/1 2>/proc/1/fd/2 &

echo "[CUSTOM-INIT] Starting WG-Easy..."
exec /usr/bin/dumb-init node server/index.mjs