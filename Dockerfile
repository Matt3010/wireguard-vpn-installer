FROM ghcr.io/wg-easy/wg-easy:15

RUN apk add --no-cache python3 py3-pip iptables conntrack-tools
WORKDIR /app

COPY config/scripts/*.py /app/

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]