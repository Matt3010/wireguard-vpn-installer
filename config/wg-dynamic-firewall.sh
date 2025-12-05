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
# FUNCTION: SAVE IPTABLES RULES
# ==============================================================================
save_iptables_rules() {
    iptables-save > /etc/iptables/rules.v4
    log_msg "[INFO] IPTables rules saved to /etc/iptables/rules.v4"
}

# ==============================================================================
# FUNCTION: APPLY FIREWALL RULES
# ==============================================================================
apply_firewall_rules() {
    log_msg "[START] Recalculating firewall rules..."

    # 1. Reset
    iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X

    # 2. Default Policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 3. Basic Rules
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT
    iptables -A INPUT -p tcp --dport 51821 -j ACCEPT

    # 4. NAT
    iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

    # 5. User Management
    if [ ! -f "$JSON_PATH" ]; then
        log_msg "[ERROR] File $JSON_PATH not found!"
        return
    fi

    jq -r '.clients | to_entries[] | select(.value.enabled == true) | "\(.value.address);\(.value.name)"' "$JSON_PATH" | \
    while IFS=";" read -r CLIENT_IP CLIENT_NAME; do

        CLIENT_IP=$(echo "$CLIENT_IP" | tr -d '[:space:]')
        CLIENT_NAME=$(echo "$CLIENT_NAME" | tr -d '[:space:]')

        # --- RESET VARIABLES ---
        ALLOW_INTERNET=false
        ALLOW_LAN=false
        LAN_PORTS="ALL"
        ROLE="⛔ DEFAULT (No Tag)"

        # --- TAG DETECTION ---
        if echo "$CLIENT_NAME" | grep -qi "_ADMIN"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=true
            ROLE="🛡️ ADMIN"
        elif echo "$CLIENT_NAME" | grep -qi "_ONLYINTERNET"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=false
            ROLE="🌍 WEB ONLY"
        elif echo "$CLIENT_NAME" | grep -qi "_LAN"; then
            ALLOW_INTERNET=false
            ALLOW_LAN=true
            ROLE="🏠 LAN FULL"

            SPECIFIC_PORT=$(echo "$CLIENT_NAME" | grep -oE "_LAN_[0-9]+(-[0-9]+)?" | sed 's/_LAN_//')
            if [ ! -z "$SPECIFIC_PORT" ]; then
                LAN_PORTS="$SPECIFIC_PORT"
                ROLE="🎯 LAN PORT $LAN_PORTS"
            fi
        fi

        # --- APPLY RULES ---
        LOG_STR="User: $CLIENT_NAME | Role: $ROLE"

        # INTERNET RULE
        if [ "$ALLOW_INTERNET" = true ]; then
            iptables -A FORWARD -i $WG_IF -o $WAN_IF -s $CLIENT_IP ! -d $LAN_SUBNET -j ACCEPT
            LOG_STR="$LOG_STR | NET: ✅"
        else
            LOG_STR="$LOG_STR | NET: ❌"
        fi

        # LAN RULE
        if [ "$ALLOW_LAN" = true ]; then
            if [ "$LAN_PORTS" == "ALL" ]; then
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -j ACCEPT
                LOG_STR="$LOG_STR | LAN: ✅ (ALL)"
            else
                IPTABLES_PORT=$(echo "$LAN_PORTS" | tr '-' ':')
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p tcp --dport "$IPTABLES_PORT" -j ACCEPT
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p udp --dport "$IPTABLES_PORT" -j ACCEPT
                LOG_STR="$LOG_STR | LAN: ✅ (Port $IPTABLES_PORT)"
            fi
        else
            LOG_STR="$LOG_STR | LAN: ❌"
        fi

        log_msg "$LOG_STR"
    done

    # Save rules after applying
    save_iptables_rules
    log_msg "[END] Rules applied."
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
