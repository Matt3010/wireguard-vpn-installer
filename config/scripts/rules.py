import re
import ipaddress
from config import ROLES_CONFIG, WG_IF, WAN_IF, LAN_SUBNET, DNS_SERVERS
from logger import log_msg, log_error

def is_valid_ip(ip):
    """
    Validates if the string is a valid IPv4 address.
    Handles CIDR notation (e.g. 10.0.0.1/32) by cleaning it before validation.
    """
    if not ip:
        return False
    try:
        # Remove CIDR part if present
        ip_clean = ip.split('/')[0]
        ipaddress.IPv4Address(ip_clean)
        return True
    except ValueError:
        return False

def is_valid_port_string(ports_str):
    """
    Strict validation: digits separated by comma or colon.
    No empty segments allowed (e.g. '80,,443' is invalid).
    """
    if not ports_str:
        return False
    # Regex: Must start with a digit, optionally followed by comma/colon and more digits.
    return bool(re.match(r'^\d+([,:]\d+)*$', ports_str))

def chunk_ports(ports_str, chunk_size=15):
    """
    Splits a port string (e.g. "80,443,8080...") into smaller chunks.
    The 'multiport' module in iptables accepts a maximum of ~15 ports per rule.
    """
    if not ports_str:
        return []

    ports = ports_str.split(',')
    # Yield sub-lists of max 'chunk_size' elements
    for i in range(0, len(ports), chunk_size):
        yield ','.join(ports[i:i + chunk_size])

def parse_roles_from_name(client_name):
    """
    Parses tags like [ADMIN] or [LAN:80] from the client name.
    Includes validation for typos and invalid port formats.
    """
    # Default Policy (Block/Restricted)
    policy = {
        "internet": False,
        "lan": False,
        "ports": None,
        "icon": "⛔ DEFAULT (No Tag)",
        "valid_config": True
    }

    # Extract all content inside square brackets: [TAG]
    matches = re.findall(r"\[([a-zA-Z0-9,:.-]+)]", client_name)

    if not matches:
        return policy

    found_valid_role = False

    for tag in matches:
        # Split "LAN:80" into "LAN" and "80"
        if ":" in tag:
            role_key, args = tag.split(":", 1)
        else:
            role_key, args = tag, None

        role_key = role_key.upper()

        # 1. Check if the Tag exists in our Config
        if role_key in ROLES_CONFIG:
            found_valid_role = True
            base_config = ROLES_CONFIG[role_key]

            # Apply base permissions
            policy["internet"] = base_config.get("internet", False)
            policy["lan"] = base_config.get("lan", False)
            policy["icon"] = base_config.get("icon", "❓")

            # 2. Special Handling for LAN Ports
            if role_key == "LAN":
                if args:
                    if is_valid_port_string(args):
                        policy["ports"] = args
                        policy["icon"] = f"🎯 LAN PORTS [{args}]"
                    else:
                        # VALIDATION ERROR: Invalid port format
                        policy["valid_config"] = False
                        policy["lan"] = False # Safety fallback: Block LAN
                        policy["icon"] = f"⚠️ INVALID PORT ({args})"
                        log_msg(f"[WARNING] Client '{client_name}' has invalid ports: '{args}'. LAN access blocked.")
                else:
                    # No ports specified -> Full Access as per config
                    policy["ports"] = "ALL"
                    policy["icon"] = "🏠 LAN FULL"

            # If we found a valid role, assume it overrides others and break
            break

        else:
            # 3. Handle Unknown Tags (Typos?)
            log_msg(f"[WARNING] Unknown tag '[{role_key}]' detected in client '{client_name}'. Check for typos.")
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
        "-A INPUT -p tcp --dport 51821 -j ACCEPT"
    ]

    # [SECURITY FIX] DNS Rules - Strict Mode
    # Only allow DNS traffic to the specifically configured DNS servers.
    # This prevents DNS tunneling abuses.
    for dns_ip in DNS_SERVERS:
        if is_valid_ip(dns_ip):
            lines.append(f"-A FORWARD -i {WG_IF} -d {dns_ip} -p udp --dport 53 -j ACCEPT")
            lines.append(f"-A FORWARD -i {WG_IF} -d {dns_ip} -p tcp --dport 53 -j ACCEPT")

    for client_id, client in clients_data.items():
        if not client.get('enabled', False):
            continue

        client_ip = client.get('address', '').strip()

        # [SECURITY] Validate IP before injecting into iptables
        if not is_valid_ip(client_ip):
            log_msg(f"[ERROR] Skipped client with invalid IP: {client_ip}")
            continue

        raw_name = client.get('name', '')
        # Sanitize for comments
        safe_name_comment = re.sub(r'[^a-zA-Z0-9 \[\]:.,_-]', '', raw_name)

        current_policy = parse_roles_from_name(raw_name)

        log_str = f"User: {safe_name_comment:<20} | Role: {current_policy['icon']}"

        # INTERNET Rule
        if current_policy['internet']:
            # Blocks LAN, but DNS (port 53) was accepted above via specific rules
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

            elif ports and current_policy['valid_config']:
                # [FIX] Handle multiport limit (chunking)
                try:
                    port_chunks = list(chunk_ports(ports, 15))
                    for chunk in port_chunks:
                        lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p tcp -m multiport --dports {chunk} -j ACCEPT")
                        lines.append(f"-A FORWARD -i {WG_IF} -s {client_ip} -d {LAN_SUBNET} -p udp -m multiport --dports {chunk} -j ACCEPT")

                    log_str += f" | LAN: ✅ (Ports: {ports})"
                except Exception as e:
                    log_error(f"Generating port rules for {safe_name_comment}", e)
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

def generate_ip6tables_block_content():
    """Generates rules to BLOCK IPv6 traffic but allow system output."""
    lines = [
        "*filter",
        ":INPUT DROP [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT ACCEPT [0:0]",
        "# Allow Loopback (Crucial for system stability)",
        "-A INPUT -i lo -j ACCEPT",
        "-A OUTPUT -o lo -j ACCEPT",
        "COMMIT"
    ]
    return "\n".join(lines) + "\n"