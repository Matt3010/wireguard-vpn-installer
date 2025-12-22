This project is a custom extension of WG-Easy (a web-based manager for WireGuard). It wraps the original application to add a dynamic, role-based Firewall and ACL system powered by Python and iptables.

Instead of giving every VPN client full access to the network, this system allows the administrator to define access levels directly within the client's name using Tags.

Key Features

Tag-Based Permissions: The system parses the WireGuard configuration (wg0.conf) looking for specific tags in the client's name (e.g., MyPhone [ADMIN]).

Dynamic Firewall: A Python background service monitors configuration changes in real-time. When a client is added or modified, it automatically generates and applies the corresponding iptables rules.

Security & cleanup: It includes a mechanism to flush connections (conntrack) for specific IPs when their permissions change, ensuring revoked access is cut off immediately.

Containerized: It is built as a Docker container that initiates the firewall manager before starting the standard WG-Easy Node.js server.

Available Roles (defined in config.py):

[ADMIN]: Full access to Internet and all LAN ports.

[ONLYINTERNET]: Access to the Internet only; LAN traffic is blocked.

[LAN]: Full access to LAN resources; Internet access is blocked.

[HYBRID]: Internet access + access to specific LAN ports (e.g., [HYBRID:80,443]).
