import os
import subprocess

def get_wan_interface():
    """
    Automatically detects the default network interface (gateway).
    Falls back to 'eth0' if detection fails.
    """
    try:
        route = subprocess.check_output(["ip", "route", "get", "8.8.8.8"]).decode().strip()
        parts = route.split()
        if "dev" in parts:
            idx = parts.index("dev") + 1
            if idx < len(parts):
                return parts[idx]
    except Exception:
        pass
    return "eth0"

# Paths
LOGFILE = "/etc/wireguard/wg-firewall.log"
WG_CONF_PATH = "/etc/wireguard/wg0.conf"
RULES_V4_PATH = "/etc/wireguard/iptables.rules.v4"
HEARTBEAT_FILE = "/tmp/firewall_heartbeat"

# Network Interfaces
WAN_IF = get_wan_interface()
WG_IF = "wg0"

# Local Subnets (IPv4)
_raw_subnets = os.getenv("WG_LAN_SUBNET", "192.168.1.0/24")
LAN_SUBNETS = [s.strip() for s in _raw_subnets.split(',') if s.strip()]


# DNS Configuration
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