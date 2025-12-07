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

# ------------------------------------------------------------------------------
# ROLE DEFINITIONS
# ------------------------------------------------------------------------------
ROLES_CONFIG = {
    "ADMIN": {
        "internet": True,
        "lan": True,
        "ports": "ALL",
        "icon": "🛡️ ADMIN"
    },
    "ONLYINTERNET": {
        "internet": True,
        "lan": False,
        "ports": None,
        "icon": "🌍 WEB ONLY"
    },
    "LAN": {
        "internet": False,
        "lan": True,
        "ports": "ALL",
        "icon": "🏠 LAN FULL"
    }
}

# Logging Setup
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_msg(message):
    """Logs to file and prints to stdout."""
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
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
        log_msg(f"[INFO] IPTables rules saved to {RULES_V4_PATH}")
    except Exception as e:
        log_msg(f"[ERROR] Could not save rules: {e}")

def parse_roles_from_name(client_name):
    """
    Parses tags like [ADMIN] or [LAN:80:90,8080] from the client name.
    """
    # Default Policy (No Access)
    policy = {
        "internet": False,
        "lan": False,
        "ports": None,
        "icon": "⛔ DEFAULT (No Tag)"
    }

    # Regex to capture content inside square brackets
    # Matches: [ADMIN], [LAN], [LAN:80], [LAN:80:90,443]
    # Note: Allowed chars include ':' for ranges and ',' for lists.
    matches = re.findall(r"\[([a-zA-Z0-9,:.-]+)]", client_name)

    for tag in matches:
        # Split Tag into ROLE and ARGS (e.g. "LAN:80" -> "LAN", "80")
        # split(":", 1) ensures we only split on the FIRST colon (Role separator)
        # Subsequent colons (e.g., in 80:90) remain part of args.
        if ":" in tag:
            role_key, args = tag.split(":", 1)
        else:
            role_key, args = tag, None

        role_key = role_key.upper()

        # Check if this Key exists in our Config
        if role_key in ROLES_CONFIG:
            policy = ROLES_CONFIG[role_key].copy()

            # Handle specific port overrides for LAN role
            if role_key == "LAN":
                if args:
                    # Case: [LAN:80,443] or [LAN:80:90,8080]
                    # We pass 'args' directly to iptables.
                    # User must strictly use iptables syntax (colons for ranges).
                    policy["ports"] = args
                    policy["icon"] = f"🎯 LAN PORTS [{args}]"
                else:
                    # Case: [LAN] (No args) -> Defaults to ALL ports
                    policy["ports"] = "ALL"
                    policy["icon"] = "🏠 LAN FULL"

            # Stop after finding the first valid tag
            break

    return policy

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

        # Sanitize name for comments
        safe_name_comment = re.sub(r'[^a-zA-Z0-9 \[\]:.,_-]', '', raw_name)

        # --- PARSE POLICY ---
        current_policy = parse_roles_from_name(raw_name)

        # --- APPLY RULES ---
        log_str = f"User: {safe_name_comment:<25} | Role: {current_policy['icon']}"

        # INTERNET Rule
        if current_policy['internet']:
            lines.append(f"-A FORWARD -i {WG_IF} -o {WAN_IF} -s {client_ip} ! -d {LAN_SUBNET} -j ACCEPT")
            log_str += " | NET: ✅"
        else:
            log_str += " | NET: ❌"

        # LAN Rule
        if current_policy['lan']:
            ports = current_policy['ports']

            if ports == "ALL":
                # [LAN] -> Full Access
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -j ACCEPT")
                log_str += " | LAN: ✅ (ALL)"
            elif ports:
                # [LAN:...] -> Specific Ports
                # Directly uses user input. Format MUST be valid for iptables multiport.
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p tcp -m multiport --dports {ports} -j ACCEPT")
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p udp -m multiport --dports {ports} -j ACCEPT")
                log_str += f" | LAN: ✅ (Ports: {ports})"
            else:
                log_str += " | LAN: ❌ (Error)"
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
    if os.path.exists(RULES_V4_PATH):
        try:
            with open(RULES_V4_PATH, "r") as f:
                subprocess.run(["iptables-restore"], stdin=f, check=True)
            log_msg("[INFO] Rules restored from rules.v4")
        except Exception:
            log_msg("[WARN] Rule restoration failed.")

    last_hash = ""
    log_msg("[WATCHER] Service started.")

    while True:
        current_hash = get_file_hash(JSON_PATH)

        if current_hash and current_hash != last_hash:
            if last_hash != "":
                log_msg("[WATCHER] Change detected in wg0.json.")
            apply_firewall_rules()
            last_hash = current_hash

        time.sleep(5)

if __name__ == "__main__":
    main()