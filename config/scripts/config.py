import os

# Paths
LOGFILE = "/etc/wireguard/wg-firewall.log"
JSON_PATH = "/etc/wireguard/wg0.json"
RULES_V4_PATH = "/etc/wireguard/iptables.rules.v4"
RULES_V6_PATH = "/etc/wireguard/iptables.rules.v6"

# Network Interfaces
WAN_IF = "eth0"
WG_IF = "wg0"

LAN_SUBNET = os.getenv("WG_LAN_SUBNET", "192.168.1.0/24")

# DNS Configuration
# We allow DNS queries ONLY to the servers defined in WG_DEFAULT_DNS.
# This prevents DNS tunneling to arbitrary servers.
# If multiple DNS are specified (comma separated), we parse them into a list.
_raw_dns = os.getenv("WG_DEFAULT_DNS", "1.1.1.1")
DNS_SERVERS = [ip.strip() for ip in _raw_dns.split(',')]

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