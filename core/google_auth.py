"""
Google OAuth ID Token Verification Module
=========================================
Cryptographically validates Google ID tokens against Google's token verification
endpoint or local public keys. Enforces issuer, audience, expiration, and
verified email claims.
"""

import os
import time
import logging
from typing import Optional, Dict, Any, Callable
import requests

logger = logging.getLogger(__name__)

# Test hook allowing unit/integration tests to inject mock verification without network calls
_mock_verifier: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None


def set_mock_google_verifier(verifier: Optional[Callable[[str, Optional[str]], Dict[str, Any]]]) -> None:
    """Set or clear a custom mock verifier function for tests."""
    global _mock_verifier
    _mock_verifier = verifier


def verify_google_id_token(id_token: str, client_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Verifies a Google ID token and returns authenticated claims.
    
    Validates:
      1. Token non-empty and well-formed.
      2. Signature and claims via Google's tokeninfo service.
      3. Issuer matches accounts.google.com or https://accounts.google.com.
      4. Token is not expired.
      5. Audience matches GOOGLE_CLIENT_ID if configured.
      6. email_verified is True.
    
    Returns:
      Dict with 'email', 'name', 'picture', 'sub'.
      
    Raises:
      ValueError if verification fails.
    """
    if not id_token or not isinstance(id_token, str) or not id_token.strip():
        raise ValueError("Google ID token is required and cannot be empty")

    token_str = id_token.strip()

    # Use mock verifier if set (for unit/integration testing)
    if _mock_verifier is not None:
        return _mock_verifier(token_str, client_id)

    expected_client_id = client_id or os.environ.get("GOOGLE_CLIENT_ID")
    if not expected_client_id:
        raise ValueError("GOOGLE_CLIENT_ID configuration is required. Google authentication failed closed.")

    try:
        url = "https://oauth2.googleapis.com/tokeninfo"
        resp = requests.get(url, params={"id_token": token_str}, timeout=5)
        if resp.status_code != 200:
            err_msg = resp.json().get("error_description", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            raise ValueError(f"Invalid Google ID token: {err_msg}")
        claims = resp.json()
    except requests.RequestException as ex:
        logger.error(f"Network error verifying Google ID token: {ex}")
        raise ValueError("Unable to reach Google authentication service")

    # 1. Validate issuer
    iss = claims.get("iss")
    if iss not in ("accounts.google.com", "https://accounts.google.com"):
        raise ValueError(f"Invalid Google token issuer: {iss}")

    # 2. Validate expiration
    try:
        exp = int(claims.get("exp", 0))
        if exp < time.time():
            raise ValueError("Google ID token has expired")
    except (TypeError, ValueError):
        raise ValueError("Invalid expiration claim in token")

    # 3. Validate audience (Fail Closed: mandatory configuration and match)
    aud = claims.get("aud")
    if not aud or aud != expected_client_id:
        raise ValueError(f"Google ID token audience mismatch: expected {expected_client_id}, got {aud}")

    # 4. Enforce verified email
    email_verified = claims.get("email_verified")
    if email_verified not in (True, "true", "True", 1):
        raise ValueError("Google email is not verified by Google")

    email = claims.get("email")
    if not email or not isinstance(email, str) or "@" not in email:
        raise ValueError("Token is missing a valid email claim")

    # 5. Enforce valid subject identifier
    sub = claims.get("sub")
    if not sub or not isinstance(sub, str) or not sub.strip():
        raise ValueError("Google ID token missing valid subject identifier ('sub')")

    return {
        "email": email.strip().lower(),
        "name": claims.get("name") or claims.get("given_name"),
        "picture": claims.get("picture"),
        "sub": sub.strip(),
    }
