import os
import hashlib
import subprocess
import re
from config import RULES_V4_PATH, RULES_V6_PATH
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
            'address': '10.8.0.x',      # IPv4
            'address_v6': 'fd00::x',    # IPv6 (Optional)
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
                # Format expected: # Client: m.scanferla [ADMIN] (1)
                if line.startswith("# Client:"):
                    # Regex captures: Group 1 (Name + Tags), Group 2 (ID)
                    match = re.search(r"# Client:\s*(.+)\s+\((.+)\)", line)
                    if match:
                        name = match.group(1).strip()
                        client_id = match.group(2).strip()
                        current_client = {'name': name, 'id': client_id, 'enabled': True}

                # 2. Detect AllowedIPs
                # Format expected: AllowedIPs = 10.8.0.2/32, fdcc:...
                elif line.startswith("AllowedIPs") and current_client:
                    try:
                        # Split by '=' then by ',' to handle multiple IPs (IPv4/IPv6)
                        parts = line.split("=", 1)[1].strip().split(",")
                        found_ip = False

                        for part in parts:
                            ip_cidr = part.strip()

                            # Detect IPv4
                            if "." in ip_cidr:
                                ip = ip_cidr.split("/")[0] # Remove /32
                                current_client['address'] = ip
                                found_ip = True

                            # Detect IPv6
                            elif ":" in ip_cidr:
                                ip = ip_cidr.split("/")[0] # Remove /128
                                current_client['address_v6'] = ip
                                found_ip = True

                        if found_ip:
                            # Save the client using its ID as the key
                            c_id = current_client['id']
                            clients[c_id] = current_client.copy()

                        # Reset for next peer
                        current_client = {}

                    except Exception:
                        pass

    except Exception as e:
        log_error("Parsing wg0.conf", e)

    return clients

def save_iptables_rules():
    """Saves current rules to disk (IPv4 and IPv6)."""
    try:
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)

        # Save IPv4
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)

        # Save IPv6
        with open(RULES_V6_PATH, "w") as f:
            subprocess.run(["ip6tables-save"], stdout=f, check=True)

        log_msg(f"[INFO] IPTables rules saved (v4 to {RULES_V4_PATH}, v6 to {RULES_V6_PATH})")
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
