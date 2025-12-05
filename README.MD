# Smart WireGuard VPN with Role-Based Access Control

This project sets up a **WireGuard VPN server** (using [wg-easy](https://github.com/WeeJeWel/wg-easy)) running in **Docker**, paired with a **Dynamic Firewall script**. It allows managing VPN client permissions (Internet access, LAN access, or specific ports) using **tags in the Web UI**. The system also integrates **Cloudflare DDNS** to maintain accessibility even if your home IP changes.

---

## 📋 Features

- **Web UI:** Easy management of VPN clients via wg-easy dashboard.
- **Dynamic DNS:** Automatically updates Cloudflare DNS records.
- **Role-Based Firewall:** Permissions applied automatically based on client name:
  - **Admin:** Full Internet + LAN access.
  - **Only Internet:** Internet access only.
  - **Lan:** LAN access only.

---

## 🛠 Prerequisites

- **Hardware:** Linux server (e.g., Raspberry Pi) capable of running Docker
- **Domain:** Managed by Cloudflare

## ⚙ WireGuard Port Forwarding Configuration

- **Protocol:** `UDP`
- **Remote Host IP Address:** `0.0.0.0 ~ 0.0.0.0`
- **LAN Host:** `YOUR LOCAL IP ADDRESS`
- **WAN Port:** `51820 ~ 51820`
- **LAN Host Port:** `51820`

---

## 🔐 Step 1: Cloudflare API Token Setup

1. Log in to your **Cloudflare Dashboard**.
2. Go to **My Profile → API Tokens → Create Token**.
3. Use the **"Edit Zone DNS"** template or create a **Custom Token**.
4. Configure **Permissions**:
   * `Zone Resources → Include → Specific zone → Your Domain`
5. Copy the generated **API Token**; it will be used in the `.env` file.

---

## 📂 Installation

```bash
git clone https://github.com/Matt3010/wireguard-vpn-installer.git
```

Go where **docker-compose.yml** is placed and create .env. Here an example:


```env
# --- WG-EASY CONFIGURATION ---
WG_HOST=vpn.yourdomain.com
WG_PASSWORD_HASH='$2a$10$...'  # Replace with generated bcrypt hash
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

🔐 Generating the Password Hash
Generate a bcrypt hash for the Web UI password:

[How to generate a bcrypt hash - wg-easy](https://github.com/wg-easy/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md)

Copy the output and paste it into the .env file.
---

🚀 Usage & Access Control
Start the containers:

```bash
docker compose up -d
```

Access the dashboard at: http://YOUR_SERVER_IP:51821.

The Tagging System
Rename clients in the Web UI to apply firewall rules:

| Tag in Name       | Role        | Internet | LAN Access | Description              |
|------------------|------------|:--------:|:----------:|--------------------------|
| _ADMIN           | Admin       | ✅       | ✅         | Full access              |
| _ONLYINTERNET    | Web Only    | ✅       | ❌         | Guests, no LAN access    |
| _LAN             | LAN Only    | ❌       | ✅         | Access local devices only|
| _LAN_80          | LAN Port 80 | ❌       | ✅         | Only port 80 access      |
| _LAN_8000-9000   | LAN Port Range | ❌    | ✅         | Specific port range      |
| (No Tag)         | Default     | ❌       | ❌         | Blocked by default       |

Examples:

user_ADMIN → Full access.

Guest_ONLYINTERNET → Internet only.

Printer_LAN → LAN only.

Camera_LAN_8123 → LAN access to port 8123 only.

🔍 Monitoring & Logs
Check firewall logs:

```bash
docker exec -it CONTAINER_NAME cat /var/log/wg-firewall.log
```
