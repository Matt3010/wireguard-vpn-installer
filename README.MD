# Smart WireGuard VPN with Role-Based Access Control

This project sets up a **WireGuard VPN server** (using [wg-easy](https://github.com/WeeJeWel/wg-easy)) running in **Docker**, paired with a **Dynamic Firewall script**. It allows managing VPN client permissions (Internet access, LAN access, or specific ports) using **tags in the Web UI**. The system also integrates **Cloudflare DDNS** to maintain accessibility even if your home IP changes.

---

## 📋 Features

- **Web UI:** Easy management of VPN clients via wg-easy dashboard.
- **Dynamic DNS:** Automatically updates Cloudflare DNS records.
- **Role-Based Firewall:** Permissions applied automatically based on client name:
  - **Admin:** Full Internet + LAN access.
  - **Guest/Web Only:** Internet access only.
  - **IoT/LAN Only:** LAN access only.
  - **Specific Services:** Restrict LAN access to specific ports (e.g., camera streams only).

---

## 🛠 Prerequisites

- **Hardware:** Linux server (e.g., Raspberry Pi) capable of running Docker.
- **Domain:** Managed by Cloudflare.
- **Network:** Port forwarding enabled on your router:
  - UDP `51820` → VPN traffic
  - TCP `51821` → Web Dashboard (optional if accessing locally)

---

## 🔐 Step 1: Cloudflare API Token Setup

1. Log in to your **Cloudflare Dashboard**.
2. Go to **My Profile → API Tokens → Create Token**.
3. Use the **"Edit zone DNS" template** or create a **Custom Token**.
4. Configure **Permissions**:
   - `Zone / DNS / Edit`
   - `Zone Resources → Include → Specific zone → Your Domain`
5. Copy the generated **API Token**; it will be used in the `.env` file.

---

## 📂 Installation

### 1. Directory Structure

```bash
mkdir -p ~/wireguard/config
cd ~/wireguard
2. Dynamic Firewall Script
Create the firewall script:


File: ~/wireguard/config/wg-dynamic-firewall.sh
(Paste the provided wg-dynamic-firewall.sh script content here)
Make the script executable:

bash
chmod +x ~/wireguard/config/wg-dynamic-firewall.sh
3. Docker Compose
Create docker-compose.yml:

yaml
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy
    container_name: wireguard
    environment:
      - WG_HOST=${WG_HOST}
      - PASSWORD_HASH=${WG_PASSWORD_HASH}
      - WG_PORT=${WG_PORT}
      - WG_DEFAULT_ADDRESS=${WG_DEFAULT_ADDRESS}
      - WG_DEFAULT_DNS=${WG_DEFAULT_DNS}
      - WG_ALLOWED_IPS=${WG_ALLOWED_IPS}
      - WG_MTU=${WG_MTU}
      - WG_POST_UP=${WG_POST_UP_SCRIPT}
      - WG_POST_DOWN=iptables -F; iptables -t nat -F; iptables -X
    volumes:
      - ./config:/etc/wireguard
    ports:
      - "${WG_PORT}:${WG_PORT}/udp"
      - "${WG_WEB_UI_PORT}:51821/tcp"
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1

  cloudflare-ddns:
    image: oznu/cloudflare-ddns:latest
    container_name: cf-ddns-updater
    restart: always
    environment:
      - API_KEY=${CF_API_KEY}
      - ZONE=${CF_ZONE}
      - SUBDOMAIN=${CF_SUBDOMAIN}
      - PROXIED=${CF_PROXIED}
4. Configuration (.env)
Create .env:

ini
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

🔐 Generating the Password Hash
Generate a bcrypt hash for the Web UI password:

bash

docker run --rm -it ghcr.io/wg-easy/wg-easy wgpw YOUR_PASSWORD
Copy the output (starting with $2a$10$...) and paste it into the .env file.

🚀 Usage & Access Control
Start the containers:

bash
docker compose up -d
Access the dashboard at: http://YOUR_SERVER_IP:51821.

The Tagging System
Rename clients in the Web UI to apply firewall rules:

Tag in Name	Role	Internet	LAN Access	Description
_ADMIN	Admin	✅	✅	Full access
_ONLYINTERNET	Web Only	✅	❌	Guests, no LAN access
_LAN	LAN Only	❌	✅	Access local devices only
_LAN_80	LAN Port 80	❌	✅	Only port 80 access
_LAN_8000-9000	LAN Port Range	❌	✅	Specific port range
(No Tag)	Default	❌	❌	Blocked by default

Examples:

Matteo_ADMIN → Full access.

Guest_ONLYINTERNET → Internet only.

Printer_LAN → LAN only.

Camera_LAN_8123 → LAN access to port 8123 only.

🔍 Monitoring & Logs
Check firewall logs:

bash
docker exec -it wireguard cat /var/log/wg-firewall.log
⚙️ Troubleshooting
Cannot connect VPN? Check UDP 51820 is forwarded correctly.

DDNS not updating? Ensure Cloudflare API Token is correct.

Rules not applied? Verify client names have correct tags.

🧑‍🤝‍🧑 Contributors
Project Maintainer: Matteo Scanferla