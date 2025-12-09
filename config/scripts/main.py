#!/usr/bin/env python3

import os
import time
import json
import signal
import sys
import subprocess
from config import JSON_PATH, RULES_V4_PATH, RULES_V6_PATH, HEARTBEAT_FILE, LAN_SUBNETS
from logger import log_msg, log_error, log_separator
from utils import get_file_hash, save_iptables_rules, flush_specific_ip
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
            # On failure, return old data and False
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

    # 3. Calculate Differences and Selective Flush (Only if rules applied successfully)
    try:
        ips_to_flush = set()
        all_ids = set(old_clients_data.keys()).union(set(new_clients_data.keys()))

        for client_id in all_ids:
            old_c = old_clients_data.get(client_id)
            new_c = new_clients_data.get(client_id)

            # Case 1: Client Removed
            if (old_c and not new_c):
                if old_c.get('address'): ips_to_flush.add(old_c['address'])
            
            # Case 2: Client Added
            elif (new_c and not old_c):
                if new_c.get('address'): ips_to_flush.add(new_c['address'])
            
            # Case 3: Client Modified
            elif old_c and new_c:
                # If IP changed
                if old_c.get('address') != new_c.get('address'):
                    ips_to_flush.add(old_c.get('address'))
                    ips_to_flush.add(new_c.get('address'))
                # If Enabled status or Name/Tags changed
                elif (old_c.get('enabled') != new_c.get('enabled')) or (old_c.get('name') != new_c.get('name')):
                    if new_c.get('address'): ips_to_flush.add(new_c['address'])

        if ips_to_flush:
            log_msg(f"[INFO] Flushing connections for {len(ips_to_flush)} clients.")
            for ip in ips_to_flush:
                flush_specific_ip(ip)
        else:
            log_msg("[INFO] Rules updated, no active connections require flushing.")
        
        save_iptables_rules()
        log_msg("[END] Rules applied successfully.")
        success = True
        return True, new_clients_data

    except Exception as e:
        log_error("Post-processing rules", e)
        # If flush fails, we consider it a failure to be safe
        return False, old_clients_data

def read_json_safe():
    """Reads the JSON file with retry logic to avoid race conditions."""
    max_retries = 3
    for i in range(max_retries):
        try:
            with open(JSON_PATH, 'r') as f:
                data = json.load(f)
                return data.get('clients', {})
        except json.JSONDecodeError:
            if i < max_retries - 1:
                time.sleep(0.2)
                continue
            else:
                raise
        except FileNotFoundError:
            return {}
    return {}

def main():
    # Register signal handlers for clean exit
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
    
    # Pre-load initial state
    try:
        if os.path.exists(JSON_PATH):
            last_clients_state = read_json_safe()
    except Exception:
        pass

    last_hash = ""
    log_msg(f"[WATCHER] Service started. Monitoring {JSON_PATH}...")

    log_msg(f"[INFO] Protected LAN Subnets: {LAN_SUBNETS}")

    while RUNNING:
        # Update heartbeat for Docker Healthcheck
        update_heartbeat()

        try:
            current_hash = get_file_hash(JSON_PATH)

            # Check if hash changed OR if the last update failed (empty last_hash but file exists)
            if current_hash and (current_hash != last_hash):
                
                # Debounce: wait to ensure file writing is complete
                time.sleep(0.5) 
                
                # Re-calculate hash after sleep for safety
                current_hash_after_sleep = get_file_hash(JSON_PATH)
                if current_hash != current_hash_after_sleep:
                    continue # File is still changing, skip to next cycle

                if last_hash != "":
                    log_msg("[WATCHER] Change detected in wg0.json.")

                try:
                    new_clients_data = read_json_safe()
                    
                    # EXECUTE UPDATE
                    success, resulting_state = apply_firewall_rules(last_clients_state, new_clients_data)

                    if success:
                        # UPDATE STATE ONLY ON SUCCESS
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