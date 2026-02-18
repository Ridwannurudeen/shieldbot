#!/usr/bin/env bash
# Setup HTTPS via Caddy on VPS for shieldbotsecurity.online
# Prerequisites: DNS A record for shieldbotsecurity.online -> 38.49.212.108

set -euo pipefail

echo "==> Installing Caddy..."
apt update
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install -y caddy

echo "==> Deploying Caddyfile..."
cp /opt/shieldbot/deploy/Caddyfile /etc/caddy/Caddyfile

echo "==> Restarting Caddy..."
systemctl enable caddy
systemctl restart caddy

echo "==> Caddy is running. TLS cert will be auto-provisioned."
echo "    Test: curl https://shieldbotsecurity.online/rpc/56"
