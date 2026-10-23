"""
Unit and integration tests for AI Privacy, PII Redaction, and Eastern Arabic / Indic Digit Masking.

Tests cover:
- Eastern Arabic (٠-٩) and Extended Arabic-Indic / Persian (۰-۹) digit normalization
- Egyptian phone numbers (010, 011, 012, 015) in Eastern Arabic & English numerals, with spaces, hyphens, +20, and 0020
- 14-digit National IDs in Eastern Arabic & English numerals (plain, spaces, and dashes)
- Credit card / account numbers (12-19 digits) in Eastern Arabic & English numerals (plain, spaces, and dashes)
- Credential leakage in Arabic and English (passwords, PINs, OTPs, CVVs, secrets)
- Preservation of legitimate financial questions and non-PII educational text
- describe_balance_qualitatively with Decimal, float, int, None, and negative numbers
- redact_account_number and redact_contact_info with Eastern Arabic numerals
"""
from decimal import Decimal
import pytest

from services.ai_context import (
    redact_sensitive_text,
    describe_balance_qualitatively,
    describe_savings_qualitatively,
    describe_goal_qualitatively,
    redact_name,
    redact_account_number,
    redact_contact_info,
)


# ===========================================================================
# 1. Egyptian Phone Numbers in Eastern Arabic Numerals
# ===========================================================================

@pytest.mark.parametrize("phone_input, expected_contained", [
    ("رقم تليفوني ٠١٠١٢٣٤٥٦٧٨", "[REDACTED_PHONE]"),
    ("اتصل بي على ٠١١١٢٣٤٥٦٧٨ شكراً", "[REDACTED_PHONE]"),
    ("تليفون ٠١٢١٢٣٤٥٦٧٨", "[REDACTED_PHONE]"),
    ("موبايلي ٠١٥١٢٣٤٥٦٧٨", "[REDACTED_PHONE]"),
    ("رقمي ٠١٠-١٢٣٤-٥٦٧٨ للتواصل", "[REDACTED_PHONE]"),
    ("رقمي ٠١٠ ١٢٣٤ ٥٦٧٨", "[REDACTED_PHONE]"),
    ("تليفوني +٢٠١٠١٢٣٤٥٦٧٨", "[REDACTED_PHONE]"),
    ("تليفوني ٠٠٢٠١٠١٢٣٤٥٦٧٨", "[REDACTED_PHONE]"),
    ("تواصل مع +٢٠ ١٠ ١٢٣٤ ٥٦٧٨", "[REDACTED_PHONE]"),
    ("اتصل على ٠٠٢٠ ١٠ ١٢٣٤ ٥٦٧٨", "[REDACTED_PHONE]"),
    ("تليفون (+٢٠) ٠١٠ ١٢٣٤ ٥٦٧٨", "[REDACTED_PHONE]"),
    ("رقم موبايل ۰۱۰۱۲۳۴۵۶۷۸", "[REDACTED_PHONE]"),  # Persian digits
    ("تواصل دولي +۲۰۱۰۱۲۳۴۵۶۷۸", "[REDACTED_PHONE]"),  # Persian digits with +
])
def test_eastern_arabic_phone_numbers_are_redacted(phone_input, expected_contained):
    redacted = redact_sensitive_text(phone_input)
    assert expected_contained in redacted
    assert "01012345678" not in redacted
    assert "٠١٠١٢٣٤٥٦٧٨" not in redacted


# ===========================================================================
# 2. National IDs in Eastern Arabic Numerals (14 digits)
# ===========================================================================

@pytest.mark.parametrize("id_input", [
    "الرقم القومي ٢٩٩٠١٠١١٢٣٤٥٦٧",
    "بطاقتي ٢٩٩٠١٠١١٢٣٤٥٦٧ شكراً",
    "الرقم القومي: ٢-٩٩٠١٠١-١٢٣٤٥٦-٧",
    "بطاقة رقم ٢ ٩٩٠١٠١ ١٢٣٤٥٦ ٧",
    "الرقم القومي ۲۹۹۰۱۰۱۱۲۳۴۵۶۷",  # Persian digits
    "الرقم القومي: 29901011234567",
    "National ID: 29901011234567",
    "National ID: 2-990101-123456-7",
    "National ID: 2 990101 123456 7",
])
def test_national_ids_are_redacted(id_input):
    redacted = redact_sensitive_text(id_input)
    assert "[REDACTED_ID]" in redacted
    assert "29901011234567" not in redacted
    assert "٢٩٩٠١٠١١٢٣٤٥٦٧" not in redacted


# ===========================================================================
# 3. Credit Card Numbers in Eastern Arabic and English
# ===========================================================================

@pytest.mark.parametrize("card_input, last_four", [
    ("كارتي ٤١٢٣ ٤٥٦٧ ٨٩٠١ ٢٣٤٥", "2345"),
    ("كارت ٤١٢٣-٤٥٦٧-٨٩٠١-٢٣٤٥", "2345"),
    ("بطاقة ٤١٢٣٤٥٦٧٨٩٠١٢٣٤٥", "2345"),
    ("كارت ميزة ۴۱۲۳ ۴۵۶۷ ۸۹۰۱ ۲۳۴۵", "2345"),  # Persian digits
    ("بطاقة أمريكان إكسبريس ٣٧٨٢ ٨٢٢٤٦٣ ١٠٠٠٥", "0005"),  # 15-digit Amex
    ("Card: 4123 4567 8901 2345", "2345"),
    ("Card: 4123-4567-8901-2345", "2345"),
    ("Card: 4123456789012345", "2345"),
    ("Amex: 3782 822463 10005", "0005"),
])
def test_credit_card_numbers_are_masked(card_input, last_four):
    redacted = redact_sensitive_text(card_input)
    assert f"•••• {last_four}" in redacted
    # Sensitive leading 12 digits must never appear
    assert "4123" not in redacted
    assert "٤١٢٣" not in redacted
    assert "3782" not in redacted
    assert "٣٧٨٢" not in redacted


# ===========================================================================
# 4. English Phone Numbers with +20, 0020, Spaces, and Dashes
# ===========================================================================

@pytest.mark.parametrize("phone_input", [
    "My phone is +201012345678",
    "Call me at +20 10 1234 5678 please",
    "Contact: +20-10-1234-5678",
    "Phone: +20 010 1234 5678",
    "Dial 00201012345678",
    "Dial 0020 10 1234 5678",
    "Dial 0020-10-1234-5678",
    "Dial 0020 010 1234 5678",
    "Call 010-1234-5678",
    "Call 010 1234 5678",
    "Call 01012345678",
    "Mobile 011 9876 5432",
    "Mobile 012-3456-7890",
    "Mobile 015 5555 5555",
    "Call (+20) 010 1234 5678",
])
def test_english_phone_numbers_are_redacted(phone_input):
    redacted = redact_sensitive_text(phone_input)
    assert "[REDACTED_PHONE]" in redacted
    assert "12345678" not in redacted


# ===========================================================================
# 5. Credential Leakage in Arabic and English
# ===========================================================================

@pytest.mark.parametrize("text_input, expected_credential_key", [
    ("كلمة المرور: secret123", "كلمة المرور: [REDACTED]"),
    ("الرقم السري 4321", "الرقم السري: [REDACTED]"),
    ("الرقم السري: 4321", "الرقم السري: [REDACTED]"),
    ("الرقم السري ٤٣٢١", "الرقم السري: [REDACTED]"),
    ("الرقم السري: ٤٣٢١", "الرقم السري: [REDACTED]"),
    ("كلمة السر: Pass@2026", "كلمة السر: [REDACTED]"),
    ("كلمة السر 12345", "كلمة السر: [REDACTED]"),
    ("رمز التحقق 123456", "رمز التحقق: [REDACTED]"),
    ("رمز التحقق: 123456", "رمز التحقق: [REDACTED]"),
    ("رمز التحقق ١٢٣٤٥٦", "رمز التحقق: [REDACTED]"),
    ("كود التحقق: 9876", "كود التحقق: [REDACTED]"),
    ("باسورد: secret", "باسورد: [REDACTED]"),
    ("password: secret123", "password: [REDACTED]"),
    ("password = secret123", "password: [REDACTED]"),
    ("my password is hunter2", "my password: [REDACTED]"),
    ("pin: 1234", "pin: [REDACTED]"),
    ("my pin 1234", "my pin: [REDACTED]"),
    ("pin: ١٢٣٤", "pin: [REDACTED]"),
    ("pin ١٢٣٤", "pin: [REDACTED]"),
    ("the OTP is 482913", "the OTP: [REDACTED]"),
    ("otp: 482913", "otp: [REDACTED]"),
    ("cvv: 123", "cvv: [REDACTED]"),
    ("cvv 123", "cvv: [REDACTED]"),
    ("cvv: ١٢٣", "cvv: [REDACTED]"),
    ("secret: my_secret_token", "secret: [REDACTED]"),
    ("secret = topsecret", "secret: [REDACTED]"),
])
def test_credential_leakage_is_redacted(text_input, expected_credential_key):
    redacted = redact_sensitive_text(text_input)
    assert "[REDACTED]" in redacted
    assert expected_credential_key in redacted
    # Secrets must not leak
    for secret in ["secret123", "4321", "hunter2", "Pass@2026", "482913", "topsecret"]:
        if secret in text_input:
            assert secret not in redacted


# ===========================================================================
# 6. Legitimate Financial Questions & Non-PII Text are NOT Corrupted
# ===========================================================================

@pytest.mark.parametrize("safe_question", [
    "How do I protect my kid card PIN from theft?",
    "what is a scam OTP call?",
    "How can I teach my kid to set a PIN code",
    "Why a strong password is important?",
    "كيف أحمي الرقم السري لكارت ابني من السرقة؟",
    "ما هي فوائد كلمة السر القوية؟",
    "عايز أحوش 500 جنيه كل شهر لشراء دراجة",
    "ما هي أفضل طريقة لتقسيم المصروف الأسبوعي؟",
    "هل يمكنني فتح حساب توفير بمبلغ 100 جنيه؟",
    "How can I budget 1000 EGP for school supplies?",
    "What is the 50/30/20 rule of saving?",
])
def test_legitimate_financial_questions_not_corrupted(safe_question):
    redacted = redact_sensitive_text(safe_question)
    assert "[REDACTED" not in redacted
    assert "••••" not in redacted
    assert redacted == safe_question


def test_arabic_financial_question_with_eastern_digits_remains_legible():
    """Numbers are normalized to standard digits for AI safety and processing, with no redaction false positives."""
    text = "عايز أحوش ٥٠٠ جنيه كل شهر لشراء دراجة"
    redacted = redact_sensitive_text(text)
    assert "[REDACTED" not in redacted
    assert "500" in redacted
    assert "جنيه" in redacted


def test_arabic_saving_rule_with_eastern_digits_remains_legible():
    text = "ما هي قاعدة ٥٠/٣٠/٢٠ في الادخار؟"
    redacted = redact_sensitive_text(text)
    assert "[REDACTED" not in redacted
    assert "50/30/20" in redacted


# ===========================================================================
# 7. describe_balance_qualitatively with Decimal, float, int, None, negative
# ===========================================================================

def test_describe_balance_none():
    assert describe_balance_qualitatively(None) == "zero balance (needs to earn allowance or complete chores)"


@pytest.mark.parametrize("zero_val", [0, 0.0, Decimal("0.00"), Decimal("0")])
def test_describe_balance_zero(zero_val):
    assert describe_balance_qualitatively(zero_val) == "zero balance (needs to earn allowance or complete chores)"


@pytest.mark.parametrize("neg_val", [-1, -50.0, Decimal("-10.00"), Decimal("-0.01")])
def test_describe_balance_negative(neg_val):
    assert describe_balance_qualitatively(neg_val) == "zero balance (needs to earn allowance or complete chores)"


@pytest.mark.parametrize("starter_val", [
    1,
    25.5,
    49.99,
    Decimal("25.50"),
    Decimal("49.99"),
])
def test_describe_balance_modest_starter(starter_val):
    assert describe_balance_qualitatively(starter_val) == "modest starter balance (beginning their savings journey)"


@pytest.mark.parametrize("moderate_val", [
    50,
    50.0,
    100,
    149.99,
    Decimal("50.00"),
    Decimal("100.00"),
    Decimal("149.99"),
])
def test_describe_balance_moderate(moderate_val):
    assert describe_balance_qualitatively(moderate_val) == "moderate balance (building steady savings habits)"


@pytest.mark.parametrize("healthy_val", [
    150,
    150.0,
    250.75,
    499.99,
    Decimal("150.00"),
    Decimal("300.00"),
    Decimal("499.99"),
])
def test_describe_balance_healthy(healthy_val):
    assert describe_balance_qualitatively(healthy_val) == "healthy balance (diligent saver with active money management)"


@pytest.mark.parametrize("substantial_val", [
    500,
    500.0,
    1000,
    2500.50,
    Decimal("500.00"),
    Decimal("1500.00"),
])
def test_describe_balance_substantial(substantial_val):
    assert describe_balance_qualitatively(substantial_val) == "substantial balance (experienced saver with strong financial discipline)"


@pytest.mark.parametrize("invalid_val", ["invalid", "N/A", [], {}])
def test_describe_balance_invalid_types_fail_safe(invalid_val):
    assert describe_balance_qualitatively(invalid_val) == "zero balance (needs to earn allowance or complete chores)"


def test_describe_balance_never_leaks_numeric_amount():
    """Verify that qualitative descriptions never contain numeric currency amounts."""
    for val in [Decimal("123.45"), 456.78, 1000, Decimal("9999.99")]:
        result = describe_balance_qualitatively(val)
        assert str(val) not in result
        assert "EGP" not in result
        assert "جنيه" not in result


# ===========================================================================
# 8. Helper Redaction Functions with Eastern Arabic Numerals
# ===========================================================================

def test_redact_account_number_with_eastern_arabic():
    assert redact_account_number("٤١٢٣٤٥٦٧٨٩٠١٢٣٤٥") == "•••• 2345"
    assert redact_account_number("٤١٢٣-٤٥٦٧-٨٩٠١-٢٣٤٥") == "•••• 2345"
    assert redact_account_number("4123456789012345") == "•••• 2345"
    assert redact_account_number(None) == "n/a"
    assert redact_account_number("") == "n/a"


def test_redact_contact_info_with_eastern_arabic():
    assert redact_contact_info("٠١٠١٢٣٤٥٦٧٨") == "***5678"
    assert redact_contact_info("01012345678") == "***5678"
    assert redact_contact_info("user@example.com") == "u***@example.com"
    assert redact_contact_info(None) == "[REDACTED]"


def test_describe_goal_qualitatively_redacts_pii_in_goal_name():
    """Goal names containing phone numbers or PII are sanitized before qualitative formatting."""
    goal_name = "تحويش للموبايل ٠١٠١٢٣٤٥٦٧٨"
    desc = describe_goal_qualitatively(50, 100, goal_name)
    assert "[REDACTED_PHONE]" in desc
    assert "01012345678" not in desc
    assert "٠١٠١٢٣٤٥٦٧٨" not in desc
