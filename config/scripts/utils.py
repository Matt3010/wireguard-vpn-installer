import os
import hashlib
import subprocess
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

def save_iptables_rules():
    """Saves current rules to disk."""
    try:
        os.makedirs(os.path.dirname(RULES_V4_PATH), exist_ok=True)
        with open(RULES_V4_PATH, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
        log_msg(f"[INFO] IPTables rules saved to {RULES_V4_PATH}")
    except Exception as e:
        log_error("Saving iptables rules", e)

def flush_conntrack():
    """Executes 'conntrack -F' to force flush existing connections."""
    try:
        subprocess.run(['conntrack', '-F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_msg("[INFO] Conntrack table flushed (old connections dropped).")
    except FileNotFoundError:
        log_msg("[WARN] 'conntrack' command not found. Pre-existing connections might remain active.")
    except Exception as e:
        log_error("Flushing conntrack", e)