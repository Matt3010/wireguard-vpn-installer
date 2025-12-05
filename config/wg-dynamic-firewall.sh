#!/bin/bash

# ==============================================================================
# CONFIGURAZIONE
# ==============================================================================
LOGFILE="/var/log/wg-firewall.log"
JSON_PATH="/etc/wireguard/wg0.json"
WAN_IF="eth0"
WG_IF="wg0"
LAN_SUBNET="192.168.1.0/24"

# Funzione per scrivere nel log
log_msg() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
}

# ==============================================================================
# FUNZIONE PRINCIPALE
# ==============================================================================
apply_firewall_rules() {
    log_msg "[START] Ricalcolo regole firewall..."

    # 1. Reset
    iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X

    # 2. Policy Default
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 3. Regole Base
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT
    iptables -A INPUT -p tcp --dport 51821 -j ACCEPT

    # 4. NAT
    iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

    # 5. Gestione Utenti
    if [ ! -f "$JSON_PATH" ]; then
        log_msg "[ERRORE] File $JSON_PATH non trovato!"
        return
    fi

    jq -r '.clients | to_entries[] | select(.value.enabled == true) | "\(.value.address);\(.value.name)"' "$JSON_PATH" | \
    while IFS=";" read -r CLIENT_IP CLIENT_NAME; do

        CLIENT_IP=$(echo "$CLIENT_IP" | tr -d '[:space:]')
        CLIENT_NAME=$(echo "$CLIENT_NAME" | tr -d '[:space:]')

        # --- RESET VARIABILI ---
        ALLOW_INTERNET=false
        ALLOW_LAN=false
        LAN_PORTS="ALL" # Default: tutte le porte
        ROLE="⛔ DEFAULT (No Tag)"

        # --- RILEVAMENTO TAG ---

        # 1. _ADMIN (Full)
        if echo "$CLIENT_NAME" | grep -qi "_ADMIN"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=true
            ROLE="🛡️ ADMIN"

        # 2. _ONLYINTERNET (Solo Web)
        elif echo "$CLIENT_NAME" | grep -qi "_ONLYINTERNET"; then
            ALLOW_INTERNET=true
            ALLOW_LAN=false
            ROLE="🌍 WEB ONLY"

        # 3. _LAN (Con o senza porte specifiche)
        elif echo "$CLIENT_NAME" | grep -qi "_LAN"; then
            ALLOW_INTERNET=false
            ALLOW_LAN=true
            ROLE="🏠 LAN FULL"

            # Cerca se c'è una specifica porta/range nel nome (es. _LAN_80 o _LAN_8000-9000)
            # Regex: cerca _LAN_ seguito da cifre ed eventuali trattini
            SPECIFIC_PORT=$(echo "$CLIENT_NAME" | grep -oE "_LAN_[0-9]+(-[0-9]+)?" | sed 's/_LAN_//')

            if [ ! -z "$SPECIFIC_PORT" ]; then
                LAN_PORTS="$SPECIFIC_PORT"
                ROLE="🎯 LAN PORT $LAN_PORTS"
            fi
        fi

        # --- APPLICAZIONE REGOLE ---
        LOG_STR="Utente: $CLIENT_NAME | Ruolo: $ROLE"

        # REGOLA INTERNET (Esclusa LAN)
        if [ "$ALLOW_INTERNET" = true ]; then
            iptables -A FORWARD -i $WG_IF -o $WAN_IF -s $CLIENT_IP ! -d $LAN_SUBNET -j ACCEPT
            LOG_STR="$LOG_STR | NET: ✅"
        else
            LOG_STR="$LOG_STR | NET: ❌"
        fi

        # REGOLA LAN (Con gestione porte)
        if [ "$ALLOW_LAN" = true ]; then
            if [ "$LAN_PORTS" == "ALL" ]; then
                # Accesso completo alla LAN
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -j ACCEPT
                LOG_STR="$LOG_STR | LAN: ✅ (ALL)"
            else
                # Accesso limitato a porte specifiche
                # iptables usa ':' per i range, ma nei nomi usiamo '-' (es 80-90 diventa 80:90)
                IPTABLES_PORT=$(echo "$LAN_PORTS" | tr '-' ':')

                # Apriamo sia TCP che UDP per sicurezza sulla porta indicata
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p tcp --dport "$IPTABLES_PORT" -j ACCEPT
                iptables -A FORWARD -i $WG_IF -s $CLIENT_IP -d $LAN_SUBNET -p udp --dport "$IPTABLES_PORT" -j ACCEPT

                LOG_STR="$LOG_STR | LAN: ✅ (Port $IPTABLES_PORT)"
            fi
        else
            LOG_STR="$LOG_STR | LAN: ❌"
        fi

        log_msg "$LOG_STR"
    done

    log_msg "[END] Regole applicate."
}

# ==============================================================================
# WATCHER
# ==============================================================================
file_watcher() {
    LAST_HASH=""
    while true; do
        if [ -f "$JSON_PATH" ]; then
            CURRENT_HASH=$(md5sum "$JSON_PATH" | awk '{print $1}')
            if [ "$LAST_HASH" != "$CURRENT_HASH" ]; then
                log_msg "[WATCHER] Modifica rilevata."
                apply_firewall_rules
                LAST_HASH=$CURRENT_HASH
            fi
        fi
        sleep 5
    done
}

# ==============================================================================
# AVVIO
# ==============================================================================
if ! command -v jq &> /dev/null; then apk update && apk add --no-cache jq; fi
pkill -f "sleep 5" || true
file_watcher &