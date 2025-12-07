import re
from config import ROLES_CONFIG, WG_IF, WAN_IF, LAN_SUBNET
from logger import log_msg, log_error

def parse_roles_from_name(client_name):
    """Parses tags like [ADMIN] or [LAN:80] from the client name."""
    policy = {
        "internet": False,
        "lan": False,
        "ports": None,
        "icon": "⛔ DEFAULT (No Tag)"
    }

    try:
        matches = re.findall(r"\[([a-zA-Z0-9,:.-]+)]", client_name)
        for tag in matches:
            if ":" in tag:
                role_key, args = tag.split(":", 1)
            else:
                role_key, args = tag, None

            role_key = role_key.upper()

            if role_key in ROLES_CONFIG:
                policy = ROLES_CONFIG[role_key].copy()
                if role_key == "LAN":
                    if args:
                        policy["ports"] = args
                        policy["icon"] = f"🎯 LAN PORTS [{args}]"
                    else:
                        policy["ports"] = "ALL"
                        policy["icon"] = "🏠 LAN FULL"
                break
    except Exception as e:
        log_error(f"Parsing name '{client_name}'", e)

    return policy

def generate_iptables_content(clients_data):
    """Generates the text content for iptables-restore."""
    lines = [
        "*filter",
        ":INPUT DROP [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "# Local traffic and established connections",
        "-A INPUT -i lo -j ACCEPT",
        "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "# WireGuard Ports",
        "-A INPUT -p udp --dport 51820 -j ACCEPT",
        "-A INPUT -p tcp --dport 51821 -j ACCEPT"
    ]

    for client_id, client in clients_data.items():
        if not client.get('enabled', False):
            continue

        client_ip = client.get('address', '').strip()
        raw_name = client.get('name', '')
        # Sanitize for comments
        safe_name_comment = re.sub(r'[^a-zA-Z0-9 \[\]:.,_-]', '', raw_name)

        current_policy = parse_roles_from_name(raw_name)

        log_str = f"User: {safe_name_comment:<25} | Role: {current_policy['icon']}"

        # INTERNET Rule
        if current_policy['internet']:
            lines.append(f"-A FORWARD -i {WG_IF} -o {WAN_IF} -s {client_ip} ! -d {LAN_SUBNET} -j ACCEPT")
            log_str += " | NET: ✅"
        else:
            log_str += " | NET: ❌"

        # LAN Rule
        if current_policy['lan']:
            ports = current_policy['ports']
            if ports == "ALL":
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -j ACCEPT")
                log_str += " | LAN: ✅ (ALL)"
            elif ports:
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p tcp -m multiport --dports {ports} -j ACCEPT")
                lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p udp -m multiport --dports {ports} -j ACCEPT")
                log_str += f" | LAN: ✅ (Ports: {ports})"
            else:
                log_str += " | LAN: ❌ (Error)"
        else:
            log_str += " | LAN: ❌"

        log_msg(log_str)

    lines.append("COMMIT")

    # NAT TABLE
    lines.extend([
        "*nat",
        ":PREROUTING ACCEPT [0:0]",
        ":INPUT ACCEPT [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        ":POSTROUTING ACCEPT [0:0]",
        f"-A POSTROUTING -o {WAN_IF} -j MASQUERADE",
        "COMMIT"
    ])

    return "\n".join(lines) + "\n"