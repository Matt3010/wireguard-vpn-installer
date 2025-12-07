# Paths
LOGFILE = "/etc/wireguard/wg-firewall.log"
JSON_PATH = "/etc/wireguard/wg0.json"
RULES_V4_PATH = "/etc/wireguard/iptables.rules.v4"
RULES_V6_PATH = "/etc/wireguard/iptables.rules.v6"

# Network Interfaces
WAN_IF = "eth0"
WG_IF = "wg0"
LAN_SUBNET = "192.168.1.0/24"

# UI / Logging
SEPARATOR_LINE = "-" * 60

# Roles Configuration
ROLES_CONFIG = {
    "ADMIN": {
        "internet": True,
        "lan": True,
        "ports": "ALL",
        "icon": "🛡️ ADMIN"
    },
    "ONLYINTERNET": {
        "internet": True,
        "lan": False,
        "ports": None,
        "icon": "🌍 WEB ONLY"
    },
    "LAN": {
        "internet": False,
        "lan": True,
        "ports": "ALL",
        "icon": "🏠 LAN FULL"
    }
}