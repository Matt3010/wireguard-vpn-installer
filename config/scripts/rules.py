import re
import ipaddress
from config import ROLES_CONFIG, WG_IF, WAN_IF, LAN_SUBNETS, DNS_SERVERS
from logger import log_msg, log_error

def is_valid_ip(ip):
    """Validates if the string is a valid IPv4 address."""
    if not ip:
        return False
    try:
        ip_clean = ip.split('/')[0]
        ipaddress.IPv4Address(ip_clean)
        return True
    except ValueError:
        return False


def is_valid_port_string(ports_str):
    """Strict validation: digits separated by comma or colon."""
    if not ports_str:
        return False
    return bool(re.match(r'^\d+([,:]\d+)*$', ports_str))

def chunk_ports(ports_str, chunk_size=15):
    """Splits a port string into smaller chunks for iptables multiport."""
    if not ports_str:
        return []

    ports = ports_str.split(',')
    for i in range(0, len(ports), chunk_size):
        yield ','.join(ports[i:i + chunk_size])

def parse_roles_from_name(client_name):
    """Parses tags like [ADMIN] or [LAN:80] from the client name."""
    policy = {
        "internet": False,
        "lan": False,
        "ports": None,
        "icon": "⛔ DEFAULT",
        "valid_config": True
    }

    matches = re.findall(r"\[([a-zA-Z0-9,:.-]+)]", client_name)

    if not matches:
        return policy

    found_valid_role = False

    for tag in matches:
        if ":" in tag:
            role_key, args = tag.split(":", 1)
        else:
            role_key, args = tag, None

        role_key = role_key.upper()

        if role_key in ROLES_CONFIG:
            found_valid_role = True
            base_config = ROLES_CONFIG[role_key]

            policy["internet"] = base_config.get("internet", False)
            policy["lan"] = base_config.get("lan", False)
            policy["icon"] = base_config.get("icon", "❓")
            policy["ports"] = base_config.get("ports", None)

            # Special Handling for LAN Ports
            if role_key == "LAN":
                if args:
                    if is_valid_port_string(args):
                        policy["ports"] = args
                        policy["icon"] = f"🎯 LAN PORTS [{args}]"
                    else:
                        policy["valid_config"] = False
                        policy["lan"] = False
                        policy["icon"] = f"⚠️ INVALID PORT ({args})"
                        log_msg(f"[WARNING] Client '{client_name}' invalid ports: '{args}'. LAN blocked.")
                else:
                    policy["ports"] = "ALL"
                    policy["icon"] = "🏠 LAN FULL"
            break
        else:
            log_msg(f"[WARNING] Unknown tag '[{role_key}]' in client '{client_name}'.")
            policy["icon"] = f"❓ UNKNOWN [{role_key}]"

    if not found_valid_role:
        policy["valid_config"] = False

    return policy

def generate_iptables_content(clients_data):
    """Generates the text content for iptables-restore (IPv4)."""
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
        "-A INPUT -p tcp --dport 51821 -j ACCEPT",
        "# Allow ICMP (Ping)",
        "-A INPUT -p icmp --icmp-type echo-request -j ACCEPT",
        "-A FORWARD -p icmp --icmp-type echo-request -j ACCEPT"
    ]

    # DNS Rules
    for dns_ip in DNS_SERVERS:
        if is_valid_ip(dns_ip):
            lines.append(f"-A FORWARD -i {WG_IF} -d {dns_ip} -p udp --dport 53 -j ACCEPT")
            lines.append(f"-A FORWARD -i {WG_IF} -d {dns_ip} -p tcp --dport 53 -j ACCEPT")

    for client_id, client in clients_data.items():
        if not client.get('enabled', False): continue
        client_ip = client.get('address', '').strip()
        if not is_valid_ip(client_ip): continue

        raw_name = client.get('name', '')
        safe_name_comment = re.sub(r'[^a-zA-Z0-9 \[\]:.,_-]', '', raw_name)
        current_policy = parse_roles_from_name(raw_name)

        log_str = f"[v4] User: {safe_name_comment:<20} | Role: {current_policy['icon']}"

        # INTERNET Rule
        if current_policy['internet']:
            if not current_policy['lan']:
                for subnet in LAN_SUBNETS:
                     lines.append(f"-A FORWARD -i {WG_IF} -o {WAN_IF} -s {client_ip} -d {subnet} -j DROP")
            lines.append(f"-A FORWARD -i {WG_IF} -o {WAN_IF} -s {client_ip} -j ACCEPT")
            log_str += " | NET: ✅"
        else:
            log_str += " | NET: ❌"

        # LAN Rule
        if current_policy['lan']:
            ports = current_policy['ports']
            if ports == "ALL":
                for subnet in LAN_SUBNETS:
                    lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {subnet} -j ACCEPT")
                log_str += " | LAN: ✅ (ALL)"
            elif ports and current_policy['valid_config']:
                try:
                    port_chunks = list(chunk_ports(ports, 15))
                    for chunk in port_chunks:
                        for subnet in LAN_SUBNETS:
                            lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {subnet} -p tcp -m multiport --dports {chunk} -j ACCEPT")
                            lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {subnet} -p udp -m multiport --dports {chunk} -j ACCEPT")
                    log_str += f" | LAN: ✅ (Ports: {ports})"
                except Exception as e:
                    log_error(f"Gen v4 port rules for {safe_name_comment}", e)
                    log_str += " | LAN: ❌ (Gen Err)"
            else:
                log_str += " | LAN: ❌ (Invalid/Err)"
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
