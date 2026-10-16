import pytest
from api.legal_routes import PRIVACY_POLICY_HTML, TERMS_OF_SERVICE_HTML, get_privacy_policy, get_terms_of_service


def test_privacy_policy_content():
    """Verify Privacy Policy contains all mandatory Google OAuth and COPPA elements."""
    assert "FinFamily" in PRIVACY_POLICY_HTML
    assert "Google" in PRIVACY_POLICY_HTML
    assert "COPPA" in PRIVACY_POLICY_HTML
    assert "modyhashim2006@gmail.com" in PRIVACY_POLICY_HTML
    assert "سياسة الخصوصية" in PRIVACY_POLICY_HTML
    assert "Privacy Policy" in PRIVACY_POLICY_HTML

    resp = get_privacy_policy()
    assert resp.status_code == 200
    assert "text/html" in resp.media_type


def test_terms_of_service_content():
    """Verify Terms of Service content and endpoint response."""
    assert "FinFamily" in TERMS_OF_SERVICE_HTML
    assert "شروط وأحكام الخدمة" in TERMS_OF_SERVICE_HTML
    assert "Terms of Service" in TERMS_OF_SERVICE_HTML

    resp = get_terms_of_service()
    assert resp.status_code == 200
    assert "text/html" in resp.media_type
