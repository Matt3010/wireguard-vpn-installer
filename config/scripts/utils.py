import os
import hashlib
import subprocess
import re
from config import RULES_V4_PATH
from logger import log_msg, log_error

def get_file_hash(filepath):
    """Calculates MD5 hash of a file to detect changes."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        log_error("Hashing file", e)
        return None

def parse_wg_conf(filepath):
    """
    Parses wg0.conf to extract client details.
    Returns a dict:
    {
        'client_id': {
            'name': 'Name [TAG]',
            'address': '10.8.0.x',      # IPv4 ONLY
            'enabled': True
        }
    }
    """
    clients = {}
    if not os.path.exists(filepath):
        return {}

    current_client = {}

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()

                # 1. Detect Client Header Comment
                if line.startswith("# Client:"):
                    match = re.search(r"# Client:\s*(.+)\s+\((.+)\)", line)
                    if match:
                        name = match.group(1).strip()
                        client_id = match.group(2).strip()
                        current_client = {'name': name, 'id': client_id, 'enabled': True}

                # 2. Detect AllowedIPs
                elif line.startswith("AllowedIPs") and current_client:
                    try:
                        parts = line.split("=", 1)[1].strip().split(",")
                        found_ip = False

                        for part in parts:
                            ip_cidr = part.strip()

                            # Detect IPv4 ONLY
                            if "." in ip_cidr and ":" not in ip_cidr:
                                ip = ip_cidr.split("/")[0] # Remove /32
                                current_client['address'] = ip
                                found_ip = True

                            # IPv6 ignored intentionally

                        if found_ip:
                            c_id = current_client['id']
                            clients[c_id] = current_client.copy()

                        current_client = {}

                    except Exception:
                        pass

    except Exception as e:
        log_error("Parsing wg0.conf", e)

    return clients

def save_iptables_rules():
    """Saves current IPv4 rules to disk."""
    try:
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)

        # Save IPv4
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)

        # Rimosso salvataggio IPv6

        log_msg(f"[INFO] IPTables rules saved to {RULES_V4_PATH}")
    except Exception as e:
        log_error("Saving iptables rules", e)

def flush_specific_ip(ip_address):
    """
    Removes conntrack entries ONLY for a specific IP.
    """
    if not ip_address:
        return

    log_msg(f"[CONNTRACK] Flushing connections for IP: {ip_address}")

    try:
        subprocess.run(['conntrack', '-D', '-s', ip_address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['conntrack', '-D', '-d', ip_address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass