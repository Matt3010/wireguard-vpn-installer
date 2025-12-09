# Usa l'immagine base di wg-easy v15
FROM ghcr.io/wg-easy/wg-easy:latest

# 1. Installa Python3 e iptables (necessari per il tuo script)
RUN apk add --no-cache python3 py3-pip iptables ip6tables conntrack-tools
# 2. Imposta la cartella di lavoro (wg-easy lavora in /app)
WORKDIR /app

# 4. Copia lo script di avvio e rendilo eseguibile
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# 5. Sovrascrivi il comando di avvio (CMD) per usare il NOSTRO script
CMD ["/app/start.sh"]