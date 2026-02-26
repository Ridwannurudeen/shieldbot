#!/bin/bash

BOT_TOKEN="8385839520:AAEJSBSBRZu0MFDyebvY6q5aEsLBGs6FIQ8"
CHAT_ID="1132584533"
SERVICE="shieldbot"
API_URL="https://api.shieldbotsecurity.online/health"

send_alert() {
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    -d parse_mode="Markdown" \
    -d text="$1" > /dev/null
}

# ── Check 1: systemd service ──────────────────────────────────────────────────
if ! systemctl is-active --quiet $SERVICE; then
  send_alert "🚨 *ShieldBot Alert*
Service \`$SERVICE\` is DOWN. Attempting restart..."

  systemctl restart $SERVICE
  sleep 5

  if systemctl is-active --quiet $SERVICE; then
    send_alert "✅ *ShieldBot Recovered*
Service \`$SERVICE\` restarted successfully."
  else
    send_alert "❌ *ShieldBot CRITICAL*
Service \`$SERVICE\` failed to restart. Manual intervention required."
  fi
fi

# ── Check 2: API health ───────────────────────────────────────────────────────
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$API_URL")

if [ "$HTTP_CODE" != "200" ]; then
  send_alert "🚨 *ShieldBot Alert*
API health check failed.
Endpoint: \`$API_URL\`
Response code: \`$HTTP_CODE\`"
fi
