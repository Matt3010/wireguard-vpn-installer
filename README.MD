# WireGuard VPN Installer with Role-Based Access Control

This project provides a **WireGuard VPN server** (using [wg-easy](https://github.com/WeeJeWel/wg-easy)) running in **Docker**, combined with a **dynamic firewall script**. It enables easy management of VPN client permissions (Internet, LAN, or specific ports) via tags in the Web UI. The system also integrates **Cloudflare DDNS** to keep your VPN accessible even if your public IP changes.

---

## Prerequisites

- **Hardware:** Linux server (e.g., Raspberry Pi) capable of running Docker
- **Domain:** Managed by Cloudflare

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Matt3010/wireguard-vpn-installer.git
```

Navigate to the folder containing `docker-compose.yml` and create a `.env` file. Example:

```env
# --- WG-EASY CONFIGURATION ---
WG_HOST=vpn.yourdomain.com
WG_PASSWORD_HASH=''  # Replace with generated bcrypt hash
WG_PORT=51820
WG_WEB_UI_PORT=51821
WG_DEFAULT_ADDRESS=10.8.0.x
WG_DEFAULT_DNS=1.1.1.1
WG_ALLOWED_IPS=0.0.0.0/0
WG_MTU=1420

# --- CUSTOM FIREWALL SCRIPT ---
WG_POST_UP_SCRIPT=/etc/wireguard/wg-dynamic-firewall.sh

# --- CLOUDFLARE DDNS ---
CF_API_KEY=your_cloudflare_api_token
CF_ZONE=yourdomain.com
CF_SUBDOMAIN=vpn
CF_PROXIED=false
```

### Generating the Password Hash
Generate a bcrypt hash for the Web UI password:

See: [How to generate a bcrypt hash - wg-easy](https://github.com/wg-easy/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md)

Copy the output and paste it into the `.env` file.

---

## Step 1: Cloudflare API Token Setup

1. Log in to your Cloudflare Dashboard.
2. Go to **My Profile → API Tokens → Create Token**.
3. Use the **Edit Zone DNS** template or create a custom token.
4. Set permissions:
   - Zone Resources → Include → Specific zone → Your Domain
5. Copy the generated API Token for use in the `.env` file.

---

## Cloudflare DNS Setup

Before starting, ensure your domain is added to Cloudflare and you have access to its dashboard.

1. **DNS Record:**
   - Create an `A` record for your VPN subdomain (e.g., `vpn.yourdomain.com`) pointing to your ISP public IP (static or dynamic).
   - The system can update this record automatically via DDNS.
2. **CF_PROXIED Flag:**
   - Set to `false` to expose the real IP (required for VPN traffic).
   - Set to `true` only if you want Cloudflare proxy (not recommended for VPN UDP traffic).

---

## WireGuard Port Forwarding

- **Protocol:** UDP
- **Remote Host IP:** 0.0.0.0
- **LAN Host:** Your local IP address
- **WAN Port:** 51820
- **LAN Host Port:** 51820

---

## Docker & Network Configuration

- The WireGuard container should have access to the host network for proper VPN operation. Use `network_mode: host` in `docker-compose.yml` if required.
- Ensure Docker has permissions to run scripts and access network interfaces.

---

## Usage & Access Control

**Note:** Make the firewall script executable before starting Docker:

```bash
chmod +x wg-dynamic-firewall.sh
docker compose up -d
```

Access the dashboard at: `http://YOUR_SERVER_IP:51821`

### Tagging System

Rename clients in the Web UI to apply firewall rules:

| Tag in Name         | Role           | Internet | LAN Access | Description                   |
|--------------------|----------------|:--------:|:----------:|-------------------------------|
| _ADMIN             | Admin          | ✅       | ✅         | Full access                   |
| _ONLYINTERNET      | Internet Only  | ✅       | ❌         | Guests, no LAN access         |
| _LAN               | LAN Only       | ❌       | ✅         | Access local devices only     |
| _LAN_80            | LAN Port 80    | ❌       | ✅         | Access to port 80 (or any specified port) |
| _LAN_8000-9000     | LAN Port Range | ❌       | ✅         | Access to specific port range |
| (No Tag)           | Default        | ❌       | ❌         | Blocked by default            |

**Examples:**
- `user_ADMIN` → Full access
- `Guest_ONLYINTERNET` → Internet only
- `Printer_LAN` → LAN only
- `Camera_LAN_8123` → LAN access to port 8123 only

---

## Firewall Script Notes

- The script `wg-dynamic-firewall.sh` must be executable (`chmod +x`).
- It may require root privileges to manage firewall rules.
- Log files are stored in `/var/log/wg-firewall.log` inside the container.

---

## Features

- **Web UI:** Manage VPN clients easily with wg-easy dashboard.
- **Dynamic DNS:** Automatically updates Cloudflare DNS records.
- **Role-Based Firewall:** Client permissions are set by tags in their names.

---

## Monitoring & Logs

Check firewall logs:

```bash
docker exec -it wireguard cat /var/log/wg-firewall.log
```

---

## Troubleshooting

- **Cloudflare API Errors:** Check token permissions and zone settings.
- **DNS Record Not Updating:** Verify subdomain exists and API token is correct.
- **VPN Connection Issues:** Ensure port 51820 UDP is open and forwarded correctly.
- **Firewall Script Errors:** Check script permissions and logs for details.
- **Docker Network Issues:** Use `network_mode: host` if clients cannot connect.
- **SSL/TLS:** Not required for VPN, but recommended for dashboard if exposed to the Internet.

---
