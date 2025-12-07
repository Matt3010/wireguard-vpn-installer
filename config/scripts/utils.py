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

def flush_conntrack():
    try:
        subprocess.run(['conntrack', '-F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_msg("[INFO] Conntrack table flushed.")
    except Exception as e:
        log_error("Flushing conntrack", e)