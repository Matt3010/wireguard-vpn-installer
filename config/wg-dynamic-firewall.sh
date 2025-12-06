#!/bin/bash

# ==============================================================================
# CONFIGURATION
# ==============================================================================
LOGFILE="/var/log/wg-firewall.log"
JSON_PATH="/etc/wireguard/wg0.json"
WAN_IF="eth0"
WG_IF="wg0"
LAN_SUBNET="192.168.1.0/24"

# ==============================================================================
# FUNCTION: LOGGING
# ==============================================================================
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# ==============================================================================
# FUNCTION: SAVE IPTABLES RULES (PERSISTENCE)
# ==============================================================================
save_iptables_rules() {
    iptables-save > /etc/iptables/rules.v4
    log_msg "[INFO] IPTables rules saved to /etc/iptables/rules.v4"
}

# ==============================================================================
# FUNCTION: APPLY FIREWALL RULES (ATOMIC & SANITIZED)
# ==============================================================================
apply_firewall_rules() {
    log_msg "[START] Generating atomic firewall rules..."

    # Temporary file for rules (iptables-save format)
    TMP_RULES="/tmp/iptables.rules.tmp"

    # ---------------------------------------------------------
    # 1. FILTER TABLE HEADER PREPARATION
    # ---------------------------------------------------------
    cat <<EOF > $TMP_RULES
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
# Local traffic and established connections
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
# WireGuard Ports (UDP VPN + TCP Web UI if needed internally)
-A INPUT -p udp --dport 51820 -j ACCEPT
-A INPUT -p tcp --dport 51821 -j ACCEPT
EOF

    # ---------------------------------------------------------
    # 2. USER LOGIC (PARSING JSON)
    # ---------------------------------------------------------
    if [ ! -f "$JSON_PATH" ]; then
        log_msg "[ERROR] File $JSON_PATH not found! Aborting update."
        rm $TMP_RULES
        return
    fi

    jq -r '.clients | to_entries[] | select(.value.enabled == true) | "\(.value.address);\(.value.name)"' "$JSON_PATH" | \
    while IFS=";" read -r CLIENT_IP CLIENT_NAME; do

        # --- INPUT SANITIZATION ---
        CLIENT_IP=$(echo "$CLIENT_IP" | tr -d '[:space:]')
        # Removes everything except letters, numbers, hyphens, and underscores
        CLIENT_NAME_SAFE=$(echo "$CLIENT_NAME" | sed 's/[^a-zA-Z0-9_-]//g')

        # --- RESET VARIABLES ---
        ALLOW_INTERNET=false
        ALLOW_LAN=false
        LAN_PORTS="ALL"
        ROLE="⛔ DEFAULT (No Tag)"

        # --- TAG DETECTION (Using Safe Name) ---
        if echo "$CLIENT_NAME_SAFE" | grep -qi "_ADMIN"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=true
            ROLE="🛡️ ADMIN"
        elif echo "$CLIENT_NAME_SAFE" | grep -qi "_ONLYINTERNET"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=false
            ROLE="🌍 WEB ONLY"
        elif echo "$CLIENT_NAME_SAFE" | grep -qi "_LAN"; then
            ALLOW_INTERNET=false
            ALLOW_LAN=true
            ROLE="🏠 LAN FULL"

            SPECIFIC_PORT=$(echo "$CLIENT_NAME_SAFE" | grep -oE "_LAN_[0-9]+(-[0-9]+)?" | sed 's/_LAN_//')
            if [ ! -z "$SPECIFIC_PORT" ]; then
                LAN_PORTS="$SPECIFIC_PORT"
                ROLE="🎯 LAN PORT $LAN_PORTS"
            fi
        fi

        # --- GENERATE RULES (WRITE TO FILE) ---
        LOG_STR="User: $CLIENT_NAME_SAFE | Role: $ROLE"

        # INTERNET RULE
        if [ "$ALLOW_INTERNET" = true ]; then
            echo "-A FORWARD -i $WG_IF -o $WAN_IF -s $CLIENT_IP ! -d $LAN_SUBNET -j ACCEPT" >> $TMP_RULES
            LOG_STR="$LOG_STR | NET: ✅"
        else
            LOG_STR="$LOG_STR | NET: ❌"
        fi

        # LAN RULE
        if [ "$ALLOW_LAN" = true ]; then
            if [ "$LAN_PORTS" == "ALL" ]; then
                echo "-A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -j ACCEPT" >> $TMP_RULES
                LOG_STR="$LOG_STR | LAN: ✅ (ALL)"
            else
                IPTABLES_PORT=$(echo "$LAN_PORTS" | tr '-' ':')
                echo "-A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p tcp --dport $IPTABLES_PORT -j ACCEPT" >> $TMP_RULES
                echo "-A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p udp --dport $IPTABLES_PORT -j ACCEPT" >> $TMP_RULES
                LOG_STR="$LOG_STR | LAN: ✅ (Port $IPTABLES_PORT)"
            fi
        else
            LOG_STR="$LOG_STR | LAN: ❌"
        fi

        log_msg "$LOG_STR"
    done

    # Close FILTER table
    echo "COMMIT" >> $TMP_RULES

    # ---------------------------------------------------------
    # 3. NAT TABLE HEADER PREPARATION
    # ---------------------------------------------------------
    cat <<EOF >> $TMP_RULES
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o $WAN_IF -j MASQUERADE
COMMIT
EOF

    # ---------------------------------------------------------
    # 4. ATOMIC APPLICATION
    # ---------------------------------------------------------
    iptables-restore < $TMP_RULES
    rm $TMP_RULES

    save_iptables_rules
    log_msg "[END] Atomic rules applied successfully."
}

# ==============================================================================
# FUNCTION: FILE WATCHER
# ==============================================================================
file_watcher() {
    LAST_HASH=""
    while true; do
        if [ -f "$JSON_PATH" ]; then
            CURRENT_HASH=$(md5sum "$JSON_PATH" | awk '{print $1}')
            if [ "$LAST_HASH" != "$CURRENT_HASH" ]; then
                log_msg "[WATCHER] Change detected."
                apply_firewall_rules
                LAST_HASH=$CURRENT_HASH
            fi
        fi
        sleep 5
    done
}

# ==============================================================================
# START SCRIPT
# ==============================================================================

# Restore previous rules if exist
if [ -f /etc/iptables/rules.v4 ]; then
    iptables-restore < /etc/iptables/rules.v4
    log_msg "[INFO] IPTables rules restored from /etc/iptables/rules.v4"
fi

# Ensure jq is installed
if ! command -v jq &> /dev/null; then
    apk update && apk add --no-cache jq
fi

# Kill old watcher instances
pkill -f "sleep 5" || true

# Start file watcher
file_watcher &