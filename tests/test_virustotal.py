from types import SimpleNamespace

import httpx

from backend.app.core.config import settings
from backend.app.engines import virustotal as vt


def response(status=200, payload=None):
    return SimpleNamespace(status_code=status, json=lambda: payload, headers={"content-type": "application/json"})


def setup(monkeypatch, key="test-key"):
    monkeypatch.setattr(settings, "virustotal_api_key", key)
    monkeypatch.setattr(settings, "virustotal_max_retries", 0)
    monkeypatch.setattr(settings, "virustotal_retry_backoff_seconds", 0)
    monkeypatch.setattr(settings, "virustotal_cache_ttl_seconds", 900)
    monkeypatch.setattr(vt, "normalize_url", lambda url: (url, "example.com"))
    vt.clear_cache()


def report_payload(stats=None):
    stats = stats or {"malicious": 2, "suspicious": 1, "harmless": 10, "undetected": 3}
    return {"data": {"id": "u-test", "attributes": {
        "last_analysis_stats": stats,
        "last_analysis_date": 1700000000,
        "reputation": -4,
        "categories": {"Engine": "phishing"},
        "last_analysis_results": {"Engine": {"category": "malicious", "result": "phishing", "method": "blacklist"}},
    }}}


def test_missing_and_invalid_credentials(monkeypatch):
    setup(monkeypatch, "")
    assert vt.lookup_url("https://example.com")["status"] == "not_configured"
    setup(monkeypatch)
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(401, {"error": {"message": "Invalid API key"}}))
    assert vt.lookup_url("https://example.com")["status"] == "invalid_credentials"


def test_existing_report_is_parsed_and_cached(monkeypatch):
    setup(monkeypatch)
    calls = []
    monkeypatch.setattr(vt.httpx, "get", lambda url, **k: (calls.append(url) or response(payload=report_payload())))
    result = vt.lookup_url("https://example.com")
    assert result["status"] == "queried"
    assert result["verdict"] == "malicious"
    assert result["total_engines"] == 16
    assert result["malicious_detections"] == 2
    assert result["community_reputation"] == -4
    assert result["engines"][0]["result"] == "phishing"
    cached = vt.lookup_url("https://example.com")
    assert cached["cache"] == "hit"
    assert len(calls) == 1


def test_not_found_does_not_submit_automatically(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(404, {"error": {"message": "Not found"}}))
    assert vt.lookup_url("https://example.com")["status"] == "not_found"


def test_submission_requires_explicit_consent_and_returns_analysis_id(monkeypatch):
    setup(monkeypatch)
    assert vt.submit_url("https://example.com", False)["status"] == "consent_required"
    monkeypatch.setattr(vt.httpx, "post", lambda *a, **k: response(200, {"data": {"id": "analysis-1"}}))
    result = vt.submit_url("https://example.com", True)
    assert result["status"] == "submitted"
    assert result["analysis_id"] == "analysis-1"


def test_pending_and_completed_analysis(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(200, {"data": {"attributes": {"status": "queued"}}}))
    assert vt.poll_analysis("analysis-1")["status"] == "pending"
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(200, {"data": {"attributes": {"status": "completed"}}}))
    assert vt.poll_analysis("analysis-1")["status"] == "completed"


def test_domain_and_ip_lookup_paths(monkeypatch):
    setup(monkeypatch)
    paths = []
    monkeypatch.setattr(vt.httpx, "get", lambda url, **k: (paths.append(url) or response(payload=report_payload())))
    vt.lookup_domain("Example.COM")
    vt.lookup_ip("8.8.8.8")
    assert paths[0].endswith("/domains/example.com")
    assert paths[1].endswith("/ip_addresses/8.8.8.8")


def test_rate_quota_timeout_and_provider_failure(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(429, {"error": {"message": "Too many requests"}}))
    assert vt.lookup_url("https://example.com")["status"] == "rate_limited"
    vt.clear_cache()
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(403, {"error": {"message": "Quota exceeded"}}))
    assert vt.lookup_url("https://example.com")["status"] == "quota_exceeded"
    vt.clear_cache()
    def timeout(*a, **k): raise httpx.ReadTimeout("timeout")
    monkeypatch.setattr(vt.httpx, "get", timeout)
    assert vt.lookup_url("https://example.com")["status"] == "timeout"
    vt.clear_cache()
    monkeypatch.setattr(vt.httpx, "get", lambda *a, **k: response(503, {}))
    assert vt.lookup_url("https://example.com")["status"] == "provider_error"


def test_threats_integration_preserves_virustotal_evidence(monkeypatch):
    from backend.app.engines import threats
    setup(monkeypatch)
    monkeypatch.setattr(threats, "lookup_google_safe_browsing", lambda url: {"provider": "Google Safe Browsing", "status": "not_configured", "verdict": "unknown"})
    monkeypatch.setattr(threats, "_virustotal", lambda url: {"provider": "VirusTotal", "status": "queried", "verdict": "suspicious", "detection_stats": {"suspicious": 2}, "checked_at": "now"})
    monkeypatch.setattr(threats.httpx, "post", lambda *a, **k: response(200, {}))
    result = threats.check("https://example.com")
    assert any(item["provider"] == "VirusTotal" for item in result["findings"])
    provider = next(item for item in result["providers"] if item["provider"] == "VirusTotal")
    assert provider["detection_stats"]["suspicious"] == 2
