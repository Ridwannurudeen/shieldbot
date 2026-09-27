"""Operator alerts: Telegram messages to the chat named by TELEGRAM_ALERT_CHAT_ID."""

import logging

import aiohttp

logger = logging.getLogger(__name__)


async def send_alert(settings, text: str) -> bool:
    """Post ``text`` (Telegram Markdown) to the alert chat; True only when Telegram accepted it.

    Without a bot token and an alert chat nothing is sent. A failed post is logged by exception
    class only, since its message can carry the request URL and with it the bot token. Never raises.
    """
    bot_token = getattr(settings, "telegram_bot_token", "")
    chat_id = getattr(settings, "telegram_alert_chat_id", "")
    if not bot_token or not chat_id:
        logger.warning(
            "Telegram alert not sent: TELEGRAM_BOT_TOKEN or TELEGRAM_ALERT_CHAT_ID is not configured"
        )
        return False
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status != 200:
                    logger.warning("Telegram alert refused: HTTP %d", resp.status)
                return resp.status == 200
    except Exception as e:
        logger.error("Telegram alert failed: %s", type(e).__name__)
        return False
