#!/bin/bash

# Load secrets from .env (never hardcode tokens in scripts)
ENV_FILE="/opt/shieldbot/.env"
if [ -f "$ENV_FILE" ]; then
  export $(grep -E '^(TELEGRAM_BOT_TOKEN|TELEGRAM_ALERT_CHAT_ID)=' "$ENV_FILE" | xargs)
fi

BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
CHAT_ID="${TELEGRAM_ALERT_CHAT_ID}"
SERVICE="shieldbot"
API_URL="https://api.shieldbotsecurity.online/api/health"

send_alert() {
  if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
    echo "Telegram not configured — skipping alert"
    return
  fi
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
