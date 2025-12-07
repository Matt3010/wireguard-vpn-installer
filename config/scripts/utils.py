import os
import time
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
    """
    NUCLEAR OPTION: Flushes connections using both conntrack tool
    AND the kernel timeout trick to force-kill persistent sockets.
    """
    try:
        subprocess.run(['conntrack', '-F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

    timeout_path = "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"
    default_timeout = "432000"

    try:
        if os.path.exists(timeout_path):
            with open(timeout_path, "r") as f:
                content = f.read().strip()
                if content.isdigit():
                    default_timeout = content

            log_msg("[INFO] Applying TCP Timeout Trick (Nuclear Flush)...")
            with open(timeout_path, "w") as f:
                f.write("1")

            time.sleep(2)

            with open(timeout_path, "w") as f:
                f.write(default_timeout)

            log_msg("[INFO] Connections killed and timeout restored.")
        else:
            log_msg("[WARN] Cannot find conntrack timeout file in /proc. Skipping trick.")

    except Exception as e:
        log_error("Flushing conntrack (Timeout Method)", e)