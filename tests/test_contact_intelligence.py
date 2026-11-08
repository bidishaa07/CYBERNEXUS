from types import SimpleNamespace

from backend.app.engines import contact_intelligence


def _dns_fixture(monkeypatch):
    monkeypatch.setattr(contact_intelligence, "_txt", lambda name: [
        "v=spf1 include:_spf.example -all" if not name.startswith("_dmarc.") else "v=DMARC1; p=none"
    ])
    monkeypatch.setattr(
        contact_intelligence.dns.resolver,
        "resolve",
        lambda name, record, lifetime=4: [SimpleNamespace(exchange="mx.example.")] if record == "MX" else [],
    )


def test_indian_phone_validation_is_metadata_only(monkeypatch):
    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_url", "")
    result = contact_intelligence.phone_analysis("+919876543210")
    assert result["normalized"] == "+919876543210"
    assert result["country_code"] == 91
    assert result["status"] == "COMPLETED"
    assert result["classification"] == "UNKNOWN"
    assert result["verdict"] == "unknown"
    assert result["risk_score"] is None


def test_invalid_phone_is_not_assumed_safe(monkeypatch):
    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_url", "")
    result = contact_intelligence.phone_analysis("+910000")
    assert result["valid"] is False
    assert result["classification"] == "UNKNOWN"
    assert result["risk_score"] is None


def test_phone_provider_malicious_result_is_scored(monkeypatch):
    class Response:
        status_code = 200
        def json(self):
            return {"verdict": "scam", "confidence": 0.94, "abuse_reports": 12}

    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_url", "https://provider.test/phone")
    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_key", "test-key")
    monkeypatch.setattr(contact_intelligence.httpx, "get", lambda *args, **kwargs: Response())
    result = contact_intelligence.phone_analysis("+14155552671")
    assert result["verdict"] == "malicious"
    assert result["classification"] == "CRITICAL"
    assert result["risk_score"] == 90


def test_phone_provider_timeout_remains_unknown(monkeypatch):
    contact_intelligence._cache.clear()
    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_url", "https://provider.test/timeout")
    monkeypatch.setattr(contact_intelligence.settings, "phone_reputation_api_key", "")
    monkeypatch.setattr(contact_intelligence.httpx, "get", lambda *args, **kwargs: (_ for _ in ()).throw(contact_intelligence.httpx.TimeoutException("timeout")))
    result = contact_intelligence.phone_analysis("+14155552671")
    assert result["reputation"]["status"] == "TIMEOUT"
    assert result["classification"] == "UNKNOWN"
    assert result["risk_score"] is None


def test_gmail_is_legitimate_free_provider_not_malicious(monkeypatch):
    _dns_fixture(monkeypatch)
    monkeypatch.setattr(contact_intelligence, "check_url", lambda url: {"providers": [{"provider": "fixture", "verdict": "no_match"}], "findings": []})
    registry = [{"domain": "gmail.com", "provider_name": "Gmail", "category": "FREE_CONSUMER", "disposable": "false"}]
    result = contact_intelligence.email_analysis("user@gmail.com", registry)
    assert result["provider_category"] == "FREE_CONSUMER"
    assert result["disposable"] is False
    assert result["classification"] == "LOW"
    assert result["verdict"] == "unknown"


def test_disposable_email_is_classified_without_being_called_malicious(monkeypatch):
    _dns_fixture(monkeypatch)
    monkeypatch.setattr(contact_intelligence, "check_url", lambda url: {"providers": [], "findings": []})
    registry = [{"domain": "mailinator.com", "provider_name": "Mailinator", "category": "DISPOSABLE", "disposable": "true"}]
    result = contact_intelligence.email_analysis("user@mailinator.com", registry)
    assert result["disposable"] is True
    assert result["classification"] == "MEDIUM"
    assert result["verdict"] == "unknown"


def test_malicious_email_domain_requires_threat_evidence(monkeypatch):
    _dns_fixture(monkeypatch)
    monkeypatch.setattr(contact_intelligence, "check_url", lambda url: {"providers": [{"provider": "fixture", "verdict": "malicious"}], "findings": [{"source": "fixture"}]})
    result = contact_intelligence.email_analysis("victim@bad.example", [])
    assert result["classification"] == "CRITICAL"
    assert result["risk_score"] == 80
    assert result["evidence"]


def test_unknown_email_provider_preserves_unknown(monkeypatch):
    _dns_fixture(monkeypatch)
    monkeypatch.setattr(contact_intelligence, "check_url", lambda url: {"providers": [], "findings": []})
    result = contact_intelligence.email_analysis("user@unknown.example", [])
    assert result["provider_category"] == "UNKNOWN"
    assert result["classification"] == "UNKNOWN"
    assert result["risk_score"] is None
