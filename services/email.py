import os
import logging
from typing import Optional

from dotenv import load_dotenv

import resend

load_dotenv(override=False)

logger = logging.getLogger("finfamily.email")

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

FROM_ADDRESS = os.getenv("RESEND_FROM_ADDRESS", "FinFamily <onboarding@resend.dev>")


def send_password_reset_email(to_email: str, reset_url: Optional[str], reset_token: Optional[str] = None) -> None:
    # BUG-115 (P2): Never print or log raw password reset tokens or reset URLs
    if not RESEND_API_KEY:
        logger.warning(
            "RESEND_API_KEY is unset in environment. Password reset email skipped for recipient."
        )
        return

    # C12 / #21: The mobile app has no reset page or deep link — the parent pastes the code into the app,
    # so the raw code is shown as copyable text. The button is only added when a web frontend URL exists.
    # (token_urlsafe output is [A-Za-z0-9_-] only, so it needs no HTML escaping.)
    button_html = f"""
                <p style="margin: 24px 0;">
                    <a href="{reset_url}" style="background:#0F2D52; color:#fff; padding:12px 24px; border-radius:12px; text-decoration:none; font-weight:bold;">
                        Reset Password
                    </a>
                </p>
    """ if reset_url else ""
    code_html = f"""
                <p>Your reset code — paste it into the FinFamily app (رمز الاستعادة — الصقه في تطبيق FinFamily):</p>
                <p style="font-family:monospace; font-size:15px; background:#f3f4f6; padding:12px; border-radius:8px; word-break:break-all; user-select:all;">{reset_token}</p>
    """ if reset_token else ""

    text_lines = ["We received a request to reset your FinFamily password. This code is valid for 15 minutes."]
    if reset_token:
        text_lines += ["", "Your reset code (paste it into the FinFamily app):", reset_token]
    if reset_url:
        text_lines += ["", f"Or open this link: {reset_url}"]
    text_lines += ["", "If you didn't request this, you can safely ignore this email — your password won't change."]

    resend.Emails.send({
        "from": FROM_ADDRESS,
        "to": to_email,
        "subject": "Reset your FinFamily password",
        "html": f"""
            <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                <h2 style="color:#0F2D52;">Reset your password</h2>
                <p>We received a request to reset your FinFamily password. This code is valid for 15 minutes.</p>
                {code_html}
                {button_html}
                <p style="color:#666; font-size:13px;">
                    If you didn't request this, you can safely ignore this email — your password won't change.
                </p>
            </div>
        """,
        "text": "\n".join(text_lines),
    })


def send_password_changed_notification(to_email: str) -> None:
    """BUG-114 (P2): Security notification email dispatched immediately after password change or reset."""
    if not RESEND_API_KEY:
        logger.warning(
            "RESEND_API_KEY is unset in environment. Password changed notice skipped for recipient."
        )
        return

    try:
        resend.Emails.send({
            "from": FROM_ADDRESS,
            "to": to_email,
            "subject": "Security Alert: Your FinFamily Password Was Changed",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="color:#0F2D52;">Security Alert</h2>
                    <p>The password for your FinFamily account ({to_email}) was recently changed.</p>
                    <p>If you made this change, no further action is required.</p>
                    <p style="color:#c00; font-weight:bold;">
                        If you did not make this change, please contact support or reset your password immediately.
                    </p>
                </div>
            """,
        })
    except Exception as e:
        logger.error(f"Failed to dispatch password changed security alert to {to_email}: {e}")