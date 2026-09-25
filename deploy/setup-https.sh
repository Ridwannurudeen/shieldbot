#!/usr/bin/env bash
# SUPERSEDED: production uses nginx with certbot (deploy/README.md). Kept for history; do not run.
# Setup HTTPS via Caddy on VPS for shieldbotsecurity.online
# Prerequisites: DNS A record for shieldbotsecurity.online must point to the current VPS_IP.
# Run: VPS_IP=<current public IPv4> bash /opt/shieldbot/deploy/setup-https.sh

set -euo pipefail

: "${VPS_IP:?Set VPS_IP to the current public IPv4 from your VPS provider console}"
echo "==> DNS prerequisite: shieldbotsecurity.online must point to ${VPS_IP}"

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
