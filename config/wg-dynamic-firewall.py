#!/usr/bin/env python3

import hashlib
import json
import logging
import os
import re
import subprocess
import time

# ==============================================================================
# CONFIGURATION
# ==============================================================================
LOGFILE = "/var/log/wg-firewall.log"
JSON_PATH = "/etc/wireguard/wg0.json"
WAN_IF = "eth0"
WG_IF = "wg0"
LAN_SUBNET = "192.168.1.0/24"
RULES_V4_PATH = "/etc/wireguard/iptables.rules.v4"

# Configure Logging
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_msg(message):
    """Logs to file and prints to stdout (for Docker logs)."""
    print(message)
    logging.info(message)

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def get_file_hash(filepath):
    """Calculates MD5 hash of a file to detect changes."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

def save_iptables_rules():
    """Saves current rules for persistence."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
        log_msg(f"[INFO] IPTables rules saved to {RULES_V4_PATH}")
    except Exception as e:
        log_msg(f"[ERROR] Could not save rules: {e}")

# ==============================================================================
# FIREWALL LOGIC (RULE GENERATION)
# ==============================================================================

def generate_iptables_content(clients_data):
    """Generates the text content for iptables-restore."""

    # 1. HEADER - FILTER TABLE
    lines = [
        "*filter",
        ":INPUT DROP [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "# Local traffic and established connections",
        "-A INPUT -i lo -j ACCEPT",
        "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "# WireGuard Ports (UDP VPN + TCP Web UI if internal)",
        "-A INPUT -p udp --dport 51820 -j ACCEPT",
        "-A INPUT -p tcp --dport 51821 -j ACCEPT"
    ]

    # 2. USER LOGIC
    for client_id, client in clients_data.items():
        if not client.get('enabled', False):
            continue

        client_ip = client.get('address', '').strip()
        raw_name = client.get('name', '')

        # Sanitize Name (Only alphanumeric, hyphens, underscores)
        client_name_safe = re.sub(r'[^a-zA-Z0-9_-]', '', raw_name)

        # Reset Variables
        allow_internet = False
        allow_lan = False
        lan_ports = "ALL"
        role = "⛔ DEFAULT (No Tag)"

        # Tag Detection (Case Insensitive)
        name_upper = client_name_safe.upper()

        if "_ADMIN" in name_upper:
            allow_internet = True
            allow_lan = True
            role = "🛡️ ADMIN"
        elif "_ONLYINTERNET" in name_upper:
            allow_internet = True
            allow_lan = False
            role = "🌍 WEB ONLY"
        elif "_LAN" in name_upper:
            allow_internet = False
            allow_lan = True
            role = "🏠 LAN FULL"

            # Look for specific port patterns like _LAN_8080 or _LAN_80-90
            port_match = re.search(r"_LAN_(\d+(?:-\d+)?)", name_upper)
            if port_match:
                lan_ports = port_match.group(1)
                role = f"🎯 LAN PORT {lan_ports}"

        # Generate Log String
        log_str = f"User: {client_name_safe} | Role: {role}"

        # INTERNET Rule
        if allow_internet:
            lines.append(f"-A FORWARD -i {WG_IF} -o {WAN_IF} -s {client_ip} ! -d {LAN_SUBNET} -j ACCEPT")
            log_str += " | NET: ✅"
        else:
            log_str += " | NET: ❌"

        # LAN Rule
        if allow_lan:
            if lan_ports == "ALL":
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -j ACCEPT")
                log_str += " | LAN: ✅ (ALL)"
            else:
                # iptables uses ':' for ranges, while the tag uses '-'
                ipt_port = lan_ports.replace("-", ":")
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p tcp --dport {ipt_port} -j ACCEPT")
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p udp --dport {ipt_port} -j ACCEPT")
                log_str += f" | LAN: ✅ (Port {ipt_port})"
        else:
            log_str += " | LAN: ❌"

        log_msg(log_str)

    lines.append("COMMIT")

    # 3. NAT TABLE
    lines.extend([
        "*nat",
        ":PREROUTING ACCEPT [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        ":POSTROUTING ACCEPT [0:0]",
        f"-A POSTROUTING -o {WAN_IF} -j MASQUERADE",
        "COMMIT"
    ])

    return "\n".join(lines) + "\n"

def apply_firewall_rules():
    log_msg("[START] Generating atomic firewall rules...")

    if not os.path.exists(JSON_PATH):
        log_msg(f"[ERROR] File {JSON_PATH} not found! Aborting.")
        return

    try:
        with open(JSON_PATH, 'r') as f:
            data = json.load(f)
            clients = data.get('clients', {})
    except json.JSONDecodeError:
        log_msg("[ERROR] Invalid JSON format. Skipping update.")
        return

    rules_content = generate_iptables_content(clients)

    # Atomic Application using iptables-restore
    try:
        process = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=rules_content.encode('utf-8'))

        if process.returncode != 0:
            log_msg(f"[ERROR] iptables-restore failed: {stderr.decode('utf-8')}")
        else:
            save_iptables_rules()
            log_msg("[END] Rules applied successfully.")

    except Exception as e:
        log_msg(f"[FATAL] Subprocess execution error: {e}")

# ==============================================================================
# MAIN WATCHER LOOP
# ==============================================================================

def main():
    # Initial Restore (if exists)
    if os.path.exists(RULES_V4_PATH):
        try:
            with open(RULES_V4_PATH, "r") as f:
                subprocess.run(["iptables-restore"], stdin=f, check=True)
            log_msg("[INFO] Rules restored from rules.v4")
        except Exception:
            log_msg("[WARN] Rule restoration failed.")

    # Watcher Loop
    last_hash = ""
    log_msg("[WATCHER] Service started.")

    while True:
        current_hash = get_file_hash(JSON_PATH)

        # Update if file changed
        if current_hash and current_hash != last_hash:
            if last_hash != "": # Skip log on very first run to keep logs clean, or keep it if you prefer
                log_msg("[WATCHER] Change detected in wg0.json.")
            apply_firewall_rules()
            last_hash = current_hash

        time.sleep(5)

if __name__ == "__main__":
    main()