import os
import logging
from dotenv import load_dotenv

import resend

load_dotenv(override=False)

logger = logging.getLogger("finfamily.email")

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

FROM_ADDRESS = os.getenv("RESEND_FROM_ADDRESS", "FinFamily <onboarding@resend.dev>")


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    # BUG-115 (P2): Never print or log raw password reset tokens or reset URLs
    if not RESEND_API_KEY:
        logger.warning(
            "RESEND_API_KEY is unset in environment. Password reset email skipped for recipient."
        )
        return

    resend.Emails.send({
        "from": FROM_ADDRESS,
        "to": to_email,
        "subject": "Reset your FinFamily password",
        "html": f"""
            <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                <h2 style="color:#0F2D52;">Reset your password</h2>
                <p>We received a request to reset your FinFamily password. This link is valid for 15 minutes.</p>
                <p style="margin: 24px 0;">
                    <a href="{reset_url}" style="background:#0F2D52; color:#fff; padding:12px 24px; border-radius:12px; text-decoration:none; font-weight:bold;">
                        Reset Password
                    </a>
                </p>
                <p style="color:#666; font-size:13px;">
                    If you didn't request this, you can safely ignore this email — your password won't change.
                </p>
            </div>
        """,
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