FROM ghcr.io/wg-easy/wg-easy:15

RUN apk add --no-cache python3 conntrack-tools iptables ip6tables