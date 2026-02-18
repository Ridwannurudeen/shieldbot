#!/usr/bin/env bash
# Add nginx server block for shieldbotsecurity.online (bare domain)
# and provision SSL cert via certbot.
#
# Prerequisites: DNS A record for @ -> 38.49.212.108 must be live.
# Run: bash /opt/shieldbot/deploy/setup-bare-domain.sh

set -euo pipefail

DOMAIN="shieldbotsecurity.online"
VPS_IP="38.49.212.108"

echo "==> Checking DNS for ${DOMAIN}..."
RESOLVED=$(dig +short "${DOMAIN}" A 2>/dev/null || true)
if [ "${RESOLVED}" != "${VPS_IP}" ]; then
    echo "ERROR: ${DOMAIN} resolves to '${RESOLVED}', expected '${VPS_IP}'"
    echo "Add an A record: @ -> ${VPS_IP} in Namecheap, then re-run."
    exit 1
fi
echo "    DNS OK: ${DOMAIN} -> ${RESOLVED}"

echo "==> Issuing SSL certificate via certbot..."
certbot certonly --nginx -d "${DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email || {
    echo "Certbot failed. Trying standalone mode..."
    systemctl stop nginx
    certbot certonly --standalone -d "${DOMAIN}" --non-interactive --agree-tos --register-unsafely-without-email
    systemctl start nginx
}

echo "==> Updating nginx config..."
cat > /etc/nginx/sites-available/shieldbot <<'NGINX'
# api subdomain (existing)
server {
    listen 38.49.212.108:80;
    server_name api.shieldbotsecurity.online;
    return 301 https://$server_name$request_uri;
}

server {
    listen 38.49.212.108:443 ssl http2;
    server_name api.shieldbotsecurity.online;

    ssl_certificate /etc/nginx/ssl/api.shieldbotsecurity.online.crt;
    ssl_certificate_key /etc/nginx/ssl/api.shieldbotsecurity.online.key;

    # CORS headers for Chrome extension
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "*" always;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# bare domain
server {
    listen 38.49.212.108:80;
    server_name shieldbotsecurity.online;
    return 301 https://$server_name$request_uri;
}

server {
    listen 38.49.212.108:443 ssl http2;
    server_name shieldbotsecurity.online;

    ssl_certificate /etc/letsencrypt/live/shieldbotsecurity.online/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shieldbotsecurity.online/privkey.pem;

    # CORS headers
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "*" always;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

nginx -t && systemctl reload nginx

echo "==> Done! Test:"
echo "    curl https://${DOMAIN}/rpc/56 -X POST -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}'"
