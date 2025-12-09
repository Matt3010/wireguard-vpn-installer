import os
import hashlib
import subprocess
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

def save_iptables_rules():
    """Saves current rules to disk (IPv4 and IPv6)."""
    try:
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)

        # Save IPv4
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)

        # Save IPv6 (Block rules)
        with open(RULES_V6_PATH, "w") as f:
            subprocess.run(["ip6tables-save"], stdout=f, check=True)

        log_msg(f"[INFO] IPTables rules saved (v4 to {RULES_V4_PATH}, v6 to {RULES_V6_PATH})")
    except Exception as e:
        log_error("Saving iptables rules", e)

def flush_specific_ip(ip_address):
    """
    Removes conntrack entries ONLY for a specific IP.
    Uses -D (delete) instead of -F (flush all).
    """
    if not ip_address:
        return

    log_msg(f"[CONNTRACK] Flushing connections for IP: {ip_address}")

    # We suppress errors because if no connection exists for this IP, 
    # conntrack returns an error code, which is fine.
    try:
        # Delete connections where IP is source
        subprocess.run(['conntrack', '-D', '-s', ip_address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Delete connections where IP is destination
        subprocess.run(['conntrack', '-D', '-d', ip_address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
}