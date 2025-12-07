#!/usr/bin/env python3

import os
import time
import json
import subprocess
from config import JSON_PATH, RULES_V4_PATH, RULES_V6_PATH, LOGFILE
from logger import log_msg, log_error, log_separator
from utils import get_file_hash, save_iptables_rules, flush_conntrack
from rules import generate_iptables_content, generate_ip6tables_block_content

def apply_firewall_rules():
    """Reads JSON, generates rules via rules.py, and applies them."""
    log_separator()
    log_msg("[START] Processing firewall rules update...")

    if not os.path.exists(JSON_PATH):
        log_msg(f"[ERROR] File {JSON_PATH} not found! Aborting.")
        return

    try:
        with open(JSON_PATH, 'r') as f:
            data = json.load(f)
            clients = data.get('clients', {})
    except json.JSONDecodeError as e:
        log_error("JSON Decode Error", e)
        return
    except Exception as e:
        log_error("Reading JSON file", e)
        return

    try:
        rules_content = generate_iptables_content(clients)

        process = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=rules_content.encode('utf-8'))

        if process.returncode != 0:
            err_decoded = stderr.decode('utf-8')
            log_msg(f"[ERROR] iptables-restore (v4) failed: {err_decoded}")
            with open(LOGFILE, "a") as f:
                f.write(f"IPTABLES V4 ERROR:\n{err_decoded}\n")
            return
    except Exception as e:
        log_error("Applying IPv4 rules", e)
        return

    try:
        v6_content = generate_ip6tables_block_content()

        process_v6 = subprocess.Popen(['ip6tables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_v6, stderr_v6 = process_v6.communicate(input=v6_content.encode('utf-8'))

        if process_v6.returncode != 0:
            err_decoded = stderr_v6.decode('utf-8')
            log_msg(f"[ERROR] ip6tables-restore failed: {err_decoded}")
            with open(LOGFILE, "a") as f:
                f.write(f"IPTABLES V6 ERROR:\n{err_decoded}\n")
        else:
            save_iptables_rules()
            flush_conntrack()
            log_msg("[END] Rules applied successfully (v4 + v6 Block).")

    except Exception as e:
        log_error("Applying IPv6 rules", e)

def main():
    # Restore rules on startup (IPv4)
    if os.path.exists(RULES_V4_PATH):
        try:
            with open(RULES_V4_PATH, "r") as f:
                subprocess.run(["iptables-restore"], stdin=f, check=True)
            log_msg("[INFO] Rules restored from rules.v4 at startup")
        except Exception as e:
            log_error("Startup IPv4 rule restoration", e)

    # Restore rules on startup (IPv6)
    if os.path.exists(RULES_V6_PATH):
        try:
            with open(RULES_V6_PATH, "r") as f:
                subprocess.run(["ip6tables-restore"], stdin=f, check=True)
            log_msg("[INFO] Rules restored from rules.v6 at startup")
        except Exception as e:
            log_error("Startup IPv6 rule restoration", e)

    last_hash = ""
    log_msg("[WATCHER] Service started. Monitoring wg0.json...")

    while True:
        try:
            current_hash = get_file_hash(JSON_PATH)

            if current_hash and current_hash != last_hash:
                if last_hash != "":
                    log_msg("[WATCHER] Change detected in wg0.json.")
                apply_firewall_rules()
                last_hash = current_hash

            time.sleep(5)

        except KeyboardInterrupt:
            log_msg("[STOP] Stopping watcher...")
            break
        except Exception as e:
            log_error("Main Loop Crash", e)
            time.sleep(10)

if __name__ == "__main__":
    main()