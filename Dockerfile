FROM ghcr.io/wg-easy/wg-easy:15

# Pre-install Python3 and conntrack-tools to avoid installing them at runtime
RUN apk add --no-cache python3 conntrack-tools iptables ip6tables