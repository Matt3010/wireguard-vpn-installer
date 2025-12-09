#!/usr/bin/env python3

import os
import time
import signal
import subprocess
from config import WG_CONF_PATH, RULES_V4_PATH, HEARTBEAT_FILE, LAN_SUBNETS
from logger import log_msg, log_error, log_separator
from utils import get_file_hash, save_iptables_rules, flush_specific_ip, parse_wg_conf
from rules import generate_iptables_content, generate_ip6tables_block_content

# Global variable to handle clean shutdown
RUNNING = True

def handle_signal(signum, frame):
    """Handles SIGTERM/SIGINT to exit the loop cleanly."""
    global RUNNING
    log_msg(f"[STOP] Signal received ({signum}). Stopping service...")
    RUNNING = False

def update_heartbeat():
    """Updates a timestamp file so Docker knows the script is alive."""
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(time.time()))
    except Exception:
        pass

def apply_firewall_rules(old_clients_data, new_clients_data):
    """
    Applies the firewall rules.
    Returns a tuple: (success: bool, resulting_data: dict)
    """
    log_separator()
    log_msg("[START] Processing firewall rules update...")

    # 1. Apply IPv4 Rules (IPTables Restore)
    try:
        rules_content = generate_iptables_content(new_clients_data)
        process = subprocess.Popen(['iptables-restore'], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = process.communicate(input=rules_content.encode('utf-8'))

        if process.returncode != 0:
            err_decoded = stderr.decode('utf-8')
            log_msg(f"[ERROR] iptables-restore (v4) failed: {err_decoded}")
            return False, old_clients_data
    except Exception as e:
        log_error("Applying IPv4 rules", e)
        return False, old_clients_data

    # 2. Apply IPv6 Block (Best effort)
    try:
        v6_content = generate_ip6tables_block_content()
        subprocess.run(['ip6tables-restore'], input=v6_content.encode('utf-8'), stderr=subprocess.DEVNULL)
    except Exception as e:
        log_error("Applying IPv6 rules", e)

    # 3. Calculate Differences and Selective Flush
    try:
        ips_to_flush = set()
        all_ids = set(old_clients_data.keys()).union(set(new_clients_data.keys()))

        for client_id in all_ids:
            old_c = old_clients_data.get(client_id)
            new_c = new_clients_data.get(client_id)

            # Case 1: Client Removed (exists in old, not in new)
            # In wg0.conf, disabled clients are removed from the file, so this catches them.
            if (old_c and not new_c):
                if old_c.get('address'): ips_to_flush.add(old_c['address'])

            # Case 2: Client Added
            elif (new_c and not old_c):
                # New client, usually no connections to flush, but safe to check
                pass

            # Case 3: Client Modified
            elif old_c and new_c:
                # If IP changed
                if old_c.get('address') != new_c.get('address'):
                    ips_to_flush.add(old_c.get('address'))
                    ips_to_flush.add(new_c.get('address'))
                # If Name/Tags changed (Rules changed, so flush to force re-eval)
                elif old_c.get('name') != new_c.get('name'):
                    if new_c.get('address'): ips_to_flush.add(new_c['address'])

        if ips_to_flush:
            log_msg(f"[INFO] Flushing connections for {len(ips_to_flush)} clients.")
            for ip in ips_to_flush:
                flush_specific_ip(ip)
        else:
            log_msg("[INFO] Rules updated, no active connections require flushing.")

        save_iptables_rules()
        log_msg("[END] Rules applied successfully.")
        return True, new_clients_data

    except Exception as e:
        log_error("Post-processing rules", e)
        return False, old_clients_data

def read_conf_safe():
    """Reads the wg0.conf file with retry logic."""
    max_retries = 3
    for i in range(max_retries):
        try:
            return parse_wg_conf(WG_CONF_PATH)
        except Exception:
            if i < max_retries - 1:
                time.sleep(0.2)
                continue
            else:
                return {}
    return {}

def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Restore rules on startup (IPv4)
    if os.path.exists(RULES_V4_PATH):
        try:
            with open(RULES_V4_PATH, "r") as f:
                subprocess.run(["iptables-restore"], stdin=f, stderr=subprocess.DEVNULL)
            log_msg("[INFO] IPv4 rules restored at startup")
        except Exception:
            pass

    # Initialize client state
    last_clients_state = {}

    # Pre-load initial state from config if exists
    if os.path.exists(WG_CONF_PATH):
        last_clients_state = read_conf_safe()

    last_hash = ""
    log_msg(f"[WATCHER] Service started. Monitoring {WG_CONF_PATH}...")
    log_msg(f"[INFO] Protected LAN Subnets: {LAN_SUBNETS}")

    while RUNNING:
        update_heartbeat()

        try:
            # Monitor wg0.conf instead of json
            current_hash = get_file_hash(WG_CONF_PATH)

            if current_hash and (current_hash != last_hash):

                # Debounce
                time.sleep(0.5)
                current_hash_after_sleep = get_file_hash(WG_CONF_PATH)
                if current_hash != current_hash_after_sleep:
                    continue

                if last_hash != "":
                    log_msg("[WATCHER] Change detected in wg0.conf.")

                try:
                    # Read from CONF using the new parser
                    new_clients_data = read_conf_safe()

                    success, resulting_state = apply_firewall_rules(last_clients_state, new_clients_data)

                    if success:
                        last_clients_state = resulting_state
                        last_hash = current_hash 
                    else:
                        log_msg("[WARNING] Update failed. Will retry on next loop.")
                        time.sleep(2) 

                except Exception as e:
                    log_error("Main Loop Logic", e)

            time.sleep(2)

        except Exception as e:
            log_error("Critical Watcher Crash", e)
            time.sleep(5)

    log_msg("[STOP] Watcher service stopped.")

if __name__ == "__main__":
    main()