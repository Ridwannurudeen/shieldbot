"""
Email Service — sends transactional emails via Resend.
Fire-and-forget: errors are logged but never raised to callers.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class EmailService:
    """Lightweight Resend wrapper for transactional emails."""

    def __init__(self, api_key: str = "", from_email: str = "ShieldBot <noreply@shieldbotsecurity.online>"):
        self._api_key = api_key
        self._from_email = from_email

    def is_enabled(self) -> bool:
        return bool(self._api_key)

    async def send_beta_welcome(self, to_email: str) -> Optional[dict]:
        """Send a branded beta welcome email. Returns Resend response or None on failure."""
        if not self.is_enabled():
            return None

        try:
            import resend
            resend.api_key = self._api_key

            html = _build_beta_welcome_html(to_email)

            params: resend.Emails.SendParams = {
                "from": self._from_email,
                "to": [to_email],
                "subject": "Welcome to ShieldBot Beta",
                "html": html,
            }

            response = resend.Emails.send(params)
            logger.info(f"Beta welcome email sent to {to_email}: {response}")
            return response
        except Exception as e:
            logger.error(f"Failed to send beta welcome email to {to_email}: {e}")
            return None


def _build_beta_welcome_html(email: str) -> str:
    """Branded HTML email matching the landing page aesthetic."""
    return f"""\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#0a0e1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0e1a;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
          <!-- Header -->
          <tr>
            <td style="padding:32px 40px 24px;text-align:center;">
              <h1 style="margin:0;font-size:28px;font-weight:800;letter-spacing:-0.5px;">
                <span style="color:#00ff88;">Shield</span><span style="color:#ffffff;">Bot</span>
              </h1>
              <p style="margin:8px 0 0;color:#4a5568;font-size:13px;text-transform:uppercase;letter-spacing:2px;">
                Web3 Security Firewall
              </p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="background-color:#111827;border:1px solid #1f2937;border-radius:12px;padding:40px;">
              <h2 style="margin:0 0 16px;color:#ffffff;font-size:22px;font-weight:700;">
                You're on the list!
              </h2>
              <p style="margin:0 0 20px;color:#9ca3af;font-size:15px;line-height:1.7;">
                Thanks for signing up for the ShieldBot beta. We're building the most advanced
                real-time transaction firewall for Web3 &mdash; and you'll be among the first to use it.
              </p>
              <p style="margin:0 0 20px;color:#9ca3af;font-size:15px;line-height:1.7;">
                We'll notify you at <strong style="color:#00ff88;">{email}</strong> as soon as
                beta access is ready. In the meantime, here's how to stay connected:
              </p>
              <!-- CTA Buttons -->
              <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
                <tr>
                  <td align="center" style="padding:6px 0;">
                    <a href="https://t.me/shieldbot_bnb_bot" style="display:inline-block;background-color:#00ff88;color:#0a0e1a;text-decoration:none;font-weight:700;font-size:14px;padding:12px 28px;border-radius:8px;">
                      Try the Telegram Bot
                    </a>
                  </td>
                </tr>
              </table>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 0;">
                <tr>
                  <td align="center">
                    <a href="https://github.com/Ridwannurudeen/shieldbot" style="color:#00ff88;text-decoration:none;font-size:14px;margin:0 12px;">GitHub</a>
                    &nbsp;&middot;&nbsp;
                    <a href="https://twitter.com/Ggudman1" style="color:#00ff88;text-decoration:none;font-size:14px;margin:0 12px;">Twitter / X</a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:24px 40px;text-align:center;">
              <p style="margin:0;color:#4a5568;font-size:12px;line-height:1.6;">
                ShieldBot &mdash; Real-time Web3 transaction security<br>
                You received this because you signed up for the beta at shieldbot.xyz
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
