"""
Version & Configuration Contract Tests for FinFamily.

Verifies:
1. GET /api/app/version returns latest_version == "1.1.8" and build_number == 16 by default.
2. SHA-256 for "1.1.8" matches "1cd5f2fc7302137a5264021cc4b4f11242e422f9ffcfabc1f78136b34d3b9bb4".
3. RELEASE_APK_SHA256 mappings for 1.1.6, 1.1.7, and 1.1.8.
4. vercel.json does not leak plaintext ADMIN_EMAILS in git and contains updated version metadata.
5. .github/workflows/ci.yml synchronizes APP_VERSION ("1.1.8") and APP_BUILD_NUMBER ("16").
"""

import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from main import app, RELEASE_APK_SHA256
from db.database import engine, Base

Base.metadata.create_all(bind=engine)
app.state.limiter.enabled = False
client = TestClient(app)


def test_app_version_default_contract(monkeypatch):
    """Verify GET /api/app/version returns latest_version == '1.1.8' and build_number == 16 by default."""
    # Ensure no environment overrides affect the default fallback contract
    monkeypatch.delenv("APP_VERSION", raising=False)
    monkeypatch.delenv("APP_BUILD_NUMBER", raising=False)
    monkeypatch.delenv("APP_SHA256", raising=False)
    monkeypatch.delenv("APP_DOWNLOAD_URL", raising=False)

    res = client.get("/api/app/version")
    assert res.status_code == 200
    data = res.json()

    assert data["latest_version"] == "1.1.8"
    assert data["build_number"] == 16
    assert data["version"] == "1.1.8"
    assert data["build"] == 16
    assert data["sha256"] == "1cd5f2fc7302137a5264021cc4b4f11242e422f9ffcfabc1f78136b34d3b9bb4"
    assert "v1.1.8/app-release.apk" in data["download_url"]


def test_root_endpoint_version_default(monkeypatch):
    """Verify GET / returns version '1.1.8' by default."""
    monkeypatch.delenv("APP_VERSION", raising=False)

    res = client.get("/")
    assert res.status_code in (200, 503)
    data = res.json()
    assert data.get("version") == "1.1.8"


def test_app_version_1_1_8_sha256_match(monkeypatch):
    """Verify SHA-256 for version '1.1.8' matches the released APK digest."""
    monkeypatch.setenv("APP_VERSION", "1.1.8")
    monkeypatch.delenv("APP_SHA256", raising=False)

    res = client.get("/api/app/version")
    assert res.status_code == 200
    data = res.json()

    assert data["version"] == "1.1.8"
    assert data["sha256"] == "1cd5f2fc7302137a5264021cc4b4f11242e422f9ffcfabc1f78136b34d3b9bb4"


@pytest.mark.parametrize("version,expected_sha", [
    ("1.1.6", "d8cc70f806ddb990ba2905ccd96c1367dbd56541c09e4c189b5b243e72dd0be9"),
    ("1.1.7", "9922e96d197607a9779df5282b8ab263c965b11eb5eb3d0526e0339d2c5ae0fa"),
    ("1.1.8", "1cd5f2fc7302137a5264021cc4b4f11242e422f9ffcfabc1f78136b34d3b9bb4"),
])
def test_release_apk_sha256_dictionary_entries(monkeypatch, version, expected_sha):
    """Verify RELEASE_APK_SHA256 dictionary contains proper digests for 1.1.6, 1.1.7, and 1.1.8."""
    assert RELEASE_APK_SHA256.get(version) == expected_sha

    monkeypatch.setenv("APP_VERSION", version)
    monkeypatch.delenv("APP_SHA256", raising=False)
    data = client.get("/api/app/version").json()
    assert data["sha256"] == expected_sha


def test_vercel_json_does_not_leak_plaintext_admin_emails():
    """Verify vercel.json does not contain hardcoded plaintext ADMIN_EMAILS."""
    backend_dir = Path(__file__).resolve().parent
    vercel_path = backend_dir / "vercel.json"
    assert vercel_path.is_file(), f"vercel.json not found at {vercel_path}"

    content = vercel_path.read_text(encoding="utf-8")
    assert "ADMIN_EMAILS" not in content, "ADMIN_EMAILS key found in vercel.json!"
    assert "@gmail.com" not in content, "Plaintext email address leaked in vercel.json!"
    assert "@finfamily.com" not in content, "Plaintext email address leaked in vercel.json!"

    data = json.loads(content)
    env = data.get("env", {})
    assert "ADMIN_EMAILS" not in env
    assert env.get("APP_VERSION") == "1.1.8"
    assert env.get("APP_BUILD_NUMBER") == "16"


def test_ci_workflow_version_sync():
    """Verify .github/workflows/ci.yml synchronizes APP_VERSION 1.1.8 and build 16."""
    backend_dir = Path(__file__).resolve().parent
    ci_path = backend_dir / ".github" / "workflows" / "ci.yml"
    assert ci_path.is_file(), f"ci.yml not found at {ci_path}"

    content = ci_path.read_text(encoding="utf-8")
    assert 'APP_VERSION: "1.1.8"' in content
    assert 'APP_BUILD_NUMBER: "16"' in content
