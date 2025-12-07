#!/usr/bin/env python3

import os
import time
import json
import subprocess
from config import JSON_PATH, RULES_V4_PATH, RULES_V6_PATH, LOGFILE
from logger import log_msg, log_error, log_separator
from utils import get_file_hash, save_iptables_rules, flush_specific_ip
from rules import generate_iptables_content, generate_ip6tables_block_content

def apply_firewall_rules(old_clients_data, new_clients_data):
    """
    Applies rules based on pre-loaded data (new_clients_data).
    Returns the new data on success, or the old data on failure (logical rollback).
    """
    log_separator()
    log_msg("[START] Processing firewall rules update...")

    # 1. Apply Rules (IPTables Restore)
    # We use new_clients_data passed as argument directly to avoid re-reading files
    try:
        rules_content = generate_iptables_content(new_clients_data)
        process = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=rules_content.encode('utf-8'))

        if process.returncode != 0:
            err_decoded = stderr.decode('utf-8')
            log_msg(f"[ERROR] iptables-restore (v4) failed: {err_decoded}")
            with open(LOGFILE, "a") as f:
                f.write(f"IPTABLES V4 ERROR:\n{err_decoded}\n")
            return old_clients_data # Return old state on failure
    except Exception as e:
        log_error("Applying IPv4 rules", e)
        return old_clients_data

    # IPv6 Block
    try:
        v6_content = generate_ip6tables_block_content()
        process_v6 = subprocess.Popen(['ip6tables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_v6, stderr_v6 = process_v6.communicate(input=v6_content.encode('utf-8'))

        if process_v6.returncode != 0:
            err_decoded = stderr_v6.decode('utf-8')
            log_msg(f"[ERROR] ip6tables-restore failed: {err_decoded}")
    except Exception as e:
        log_error("Applying IPv6 rules", e)

    # 2. Calculate Differences and Selective Flush
    ips_to_flush = set()

    # Get all unique IDs from both sets
    all_ids = set(old_clients_data.keys()).union(set(new_clients_data.keys()))

    for client_id in all_ids:
        old_c = old_clients_data.get(client_id)
        new_c = new_clients_data.get(client_id)

        # Case 1: Client Removed
        if old_c and not new_c:
            ip = old_c.get('address', '').strip()
            if ip: ips_to_flush.add(ip)
            continue

        # Case 2: Client Added
        if new_c and not old_c:
            ip = new_c.get('address', '').strip()
            if ip: ips_to_flush.add(ip)
            continue

        # Case 3: Client Modified
        if old_c and new_c:
            # If IP changed (rare)
            if old_c.get('address') != new_c.get('address'):
                ips_to_flush.add(old_c.get('address'))
                ips_to_flush.add(new_c.get('address'))

            # If Enabled status changed OR Name changed (Tags are inside the name)
            elif (old_c.get('enabled') != new_c.get('enabled')) or \
                    (old_c.get('name') != new_c.get('name')):
                ip = new_c.get('address', '').strip()
                if ip: ips_to_flush.add(ip)

    # 3. Execute Flush
    if ips_to_flush:
        log_msg(f"[INFO] Detected changes for {len(ips_to_flush)} clients. Flushing connections...")
        for ip in ips_to_flush:
            flush_specific_ip(ip)
    else:
        log_msg("[INFO] Rules updated, but no active client logic changed (no flush needed).")

    save_iptables_rules()
    log_msg("[END] Rules applied successfully.")

    return new_clients_data

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

    # Initialize client state
    last_clients_state = {}

    # Pre-load state so we don't treat everyone as "New" on the very first loop
    try:
        if os.path.exists(JSON_PATH):
            with open(JSON_PATH, 'r') as f:
                data = json.load(f)
                last_clients_state = data.get('clients', {})
    except Exception:
        pass

    last_hash = ""
    log_msg("[WATCHER] Service started. Monitoring wg0.json...")

    while True:
        try:
            current_hash = get_file_hash(JSON_PATH)

            if current_hash and current_hash != last_hash:
                if last_hash != "":
                    log_msg("[WATCHER] Change detected in wg0.json.")

                # [FIX] Read JSON here safely (once)
                new_clients_data = {}
                try:
                    with open(JSON_PATH, 'r') as f:
                        data = json.load(f)
                        new_clients_data = data.get('clients', {})

                    # Pass loaded data to the logic function
                    last_clients_state = apply_firewall_rules(last_clients_state, new_clients_data)

                    last_hash = current_hash

                except json.JSONDecodeError as e:
                    log_error("JSON Decode Error", e)
                except Exception as e:
                    log_error("Reading JSON file", e)

            time.sleep(5)

        except KeyboardInterrupt:
            log_msg("[STOP] Stopping watcher...")
            break
        except Exception as e:
            log_error("Main Loop Crash", e)
            time.sleep(10)

if __name__ == "__main__":
    main()