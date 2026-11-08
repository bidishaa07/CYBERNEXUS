from types import SimpleNamespace

import httpx

from backend.app.core.config import settings
from backend.app.engines import google_safe_browsing as gsb


def response(status=200, payload=None):
    return SimpleNamespace(status_code=status, json=lambda: payload, headers={"content-type": "application/json"})


def setup(monkeypatch, key="test-key"):
    monkeypatch.setattr(settings, "google_safe_browsing_api_key", key)
    monkeypatch.setattr(settings, "google_safe_browsing_max_retries", 0)
    monkeypatch.setattr(settings, "google_safe_browsing_retry_backoff_seconds", 0)
    monkeypatch.setattr(settings, "google_cloud_project_id", "")
    gsb.clear_cache()


def test_missing_key_is_unknown_not_clean(monkeypatch):
    setup(monkeypatch, "")
    result = gsb.lookup("https://example.com")
    assert result["status"] == "not_configured"
    assert result["verdict"] == "unknown"
    assert gsb.configuration_status()["connection_status"] == "NOT_CONFIGURED"


def test_whitespace_key_is_not_configured(monkeypatch):
    setup(monkeypatch, "   ")
    assert gsb.lookup("https://example.com")["status"] == "not_configured"


def test_loaded_key_is_not_claimed_connected_before_verification(monkeypatch):
    setup(monkeypatch, "real-looking-but-test")
    assert gsb.configuration_status()["connection_status"] == "CONFIGURED_NOT_TESTED"
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(payload={}))
    assert gsb.verify_connection()["connection_status"] == "CONNECTED"


def test_clean_url(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(payload={}))
    result = gsb.lookup("https://example.com")
    assert result["status"] == "queried"
    assert result["verdict"] == "no_match"
    assert result["matches"] == []


def test_malicious_and_multiple_matches_are_normalized(monkeypatch):
    setup(monkeypatch)
    payload = {"matches": [
        {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL", "threatEntry": {"url": "https://bad.test"}},
        {"threatType": "MALWARE", "platformType": "ANY_PLATFORM", "threatEntryType": "URL", "threatEntry": {"url": "https://bad.test"}},
    ]}
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(payload=payload))
    result = gsb.lookup("https://bad.test")
    assert result["verdict"] == "malicious"
    assert result["threat_categories"] == ["MALWARE", "SOCIAL_ENGINEERING"]
    assert len(result["matches"]) == 2


def test_invalid_key_quota_rate_limit_and_server_error(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(403, {"error": {"message": "API key not valid"}}))
    assert gsb.lookup("https://example.com")["status"] == "invalid_credentials"
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(403, {"error": {"message": "Quota exceeded"}}))
    assert gsb.lookup("https://example.com")["status"] == "quota_exceeded"
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(429, {"error": {"message": "Too many requests"}}))
    assert gsb.lookup("https://example.com")["status"] == "rate_limited"
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(503, {}))
    assert gsb.lookup("https://example.com")["status"] == "provider_error"


def test_api_disabled_is_distinguished(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(403, {"error": {"message": "Safe Browsing API has not been used in project or it is disabled"}}))
    assert gsb.lookup("https://example.com")["status"] == "api_not_enabled"


def test_timeout_unexpected_response_and_retry(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(settings, "google_safe_browsing_max_retries", 1)
    calls = {"count": 0}
    def timeout_then_clean(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ReadTimeout("timed out")
        return response(payload={})
    monkeypatch.setattr(gsb.httpx, "post", timeout_then_clean)
    assert gsb.lookup("https://example.com")["status"] == "queried"
    assert calls["count"] == 2
    monkeypatch.setattr(settings, "google_safe_browsing_max_retries", 0)
    gsb.clear_cache()
    monkeypatch.setattr(gsb.httpx, "post", lambda *a, **k: response(payload={"matches": "invalid"}))
    assert gsb.lookup("https://example.com")["status"] == "invalid_response"
    def always_timeout(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")
    monkeypatch.setattr(gsb.httpx, "post", always_timeout)
    assert gsb.lookup("https://example.com")["status"] == "timeout"
