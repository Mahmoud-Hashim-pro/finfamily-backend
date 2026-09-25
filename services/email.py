import os

import resend
from dotenv import load_dotenv

load_dotenv(override=True)

RESEND_API_KEY = os.getenv("RESEND_API_KEY")
if not RESEND_API_KEY:
    raise ValueError("RESEND_API_KEY is missing from .env file")

resend.api_key = RESEND_API_KEY

# لازم يبقى دومين اتعمله verify في Resend، أو استخدم "onboarding@resend.dev" وقت
# التطوير بس (بيوصل لصندوق الإيميل بتاع الحساب المسجّل بيه الـ API key بس).
FROM_ADDRESS = os.getenv("RESEND_FROM_ADDRESS", "FinFamily <onboarding@resend.dev>")


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    resend.Emails.send({
        "from": FROM_ADDRESS,
        "to": to_email,
        "subject": "Reset your FinFamily password",
        "html": f"""
            <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                <h2 style="color:#0F2D52;">Reset your password</h2>
                <p>We received a request to reset your FinFamily password. This link is valid for 30 minutes.</p>
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