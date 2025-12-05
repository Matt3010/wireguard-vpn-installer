WireGuard VPN with Cloudflare DDNS
This project sets up a lightweight, easy-to-manage WireGuard VPN server using Docker. It includes an automated DDNS updater for Cloudflare to ensure your VPN remains accessible even if your home public IP address changes.⚠️ Security DisclaimerIMPORTANT: All API keys, hashes, passwords, and domains shown in this documentation (and the example configuration files) are EXAMPLES ONLY.Do not copy-paste credentials.You must generate your own Cloudflare API Tokens.You must generate your own Password Hash.🚀 Prerequisites
Docker & Docker Compose installed on your server/Raspberry Pi.
A domain managed by Cloudflare.
Access to your router to configure Port Forwarding.

🛠️ Configuration 
Steps 
1. Generate the Password HashTo log in to the WireGuard Web UI, you cannot use a plain text password in the .env file. You must generate a bcrypt hash.According to the official wg-easy documentation, run the following command in your terminal (replace YOUR_PASSWORD with your desired password):Bashdocker run --rm ghcr.io/wg-easy/wg-easy wqe password YOUR_PASSWORD
Output example:$2a$10$RnTp/Xq4...Copy this output. You will paste it into the .env file later.Note: When pasting the hash into the .env file, enclose it in single quotes ('...') to prevent Docker from interpreting the $ signs as variables.
2. Configure Environment VariablesCreate a file named .env in the project root and populate it.Ini, TOML# --- WIREGUARD CONFIGURATION (WG-EASY) ---
# Your public DNS address (e.g., vpn.yourdomain.com)
WG_HOST=vpn.scanferlamatteo.work

# The bcrypt hash generated in Step 1.
# USE SINGLE QUOTES to avoid parsing errors with '$'
WG_PASSWORD_HASH='$2a$10$.93O6dyhDI80eJGOl7H/OufLn6IGMv5d1k8Vmy74/lIXe1hYHIW3W'

WG_PORT=51820
WG_WEB_UI_PORT=51821
WG_DEFAULT_ADDRESS=10.8.0.x
WG_DEFAULT_DNS=1.1.1.1
WG_ALLOWED_IPS=0.0.0.0/0
WG_MTU=1420

# --- CUSTOM SCRIPTS ---
# Ensure this script exists in ./config/wg-dynamic-firewall.sh
WG_POST_UP_SCRIPT=/etc/wireguard/wg-dynamic-firewall.sh

# --- CLOUDFLARE DDNS CONFIGURATION ---
# Generate a token with "Zone:DNS:Edit" permissions
CF_API_KEY=YOUR_CLOUDFLARE_API_KEY_HERE
CF_ZONE=scanferlamatteo.work
CF_SUBDOMAIN=vpn
CF_PROXIED=false

3. Create Custom Script (If used)Your configuration references WG_POST_UP_SCRIPT. Ensure the script exists locally:Create a folder named config.Inside, create a file named wg-dynamic-firewall.sh.Make it executable: chmod +x config/wg-dynamic-firewall.sh.🌐 Network Configuration (Crucial)For the VPN to work, you must configure your Router and Cloudflare DNS correctly.A. Cloudflare DNS SettingsGo to your Cloudflare Dashboard > DNS > Records. Create an A Record:TypeNameContentProxy StatusTTLAvpnYOUR_PUBLIC_IPDNS Only (Grey Cloud)Auto⚠️ IMPORTANT: The Proxy Status must be set to DNS Only (Grey Cloud). If you set it to "Proxied" (Orange Cloud), Cloudflare will mask your IP and block the VPN traffic, as WireGuard uses UDP which Cloudflare's free proxy does not support.B. Router Port ForwardingLog in to your router admin panel and open the following port:Protocol: UDP (TCP will not work)External Port: 51820Internal Port: 51820Internal IP: The local IP address of your Docker server.▶️ UsageStart the container stack:Bashdocker-compose up -d
Accessing the UIOpen your browser and navigate to:http://YOUR_SERVER_LOCAL_IP:51821Password: The plain text password you used to generate the hash in Step 1.📄 License & CreditsThis setup relies on the excellent work of the wg-easy project.Repository: https://github.com/wg-easy/wg-easyLicense: Please refer to the repository above for license details.
