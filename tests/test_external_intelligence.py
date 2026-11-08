from types import SimpleNamespace

from backend.app.core.config import settings
from backend.app.engines import external_intelligence as ext


def response(payload, status=200):
    return SimpleNamespace(status_code=status, json=lambda: payload)


def test_otx_pulses_become_suspicious_evidence(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "otx-test")
    monkeypatch.setattr(ext.httpx, "get", lambda *a, **k: response({"pulse_info": {"count": 1, "pulses": [{"id": "p1", "name": "Campaign"}]}}))
    result = ext.lookup_otx("example.com")
    assert result["status"] == "queried"
    assert result["verdict"] == "suspicious"
    assert result["pulse_count"] == 1


def test_otx_no_match_is_not_malicious(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "otx-test")
    monkeypatch.setattr(ext.httpx, "get", lambda *a, **k: response({"pulse_info": {"count": 0, "pulses": []}}))
    assert ext.lookup_otx("example.com")["verdict"] == "no_match"


def test_opswat_verdict_and_failures(monkeypatch):
    monkeypatch.setattr(settings, "opswat_api_key", "opswat-test")
    monkeypatch.setattr(ext.httpx, "get", lambda *a, **k: response({"lookup_result": "malicious"}))
    assert ext.lookup_opswat("example.com")["verdict"] == "malicious"
    monkeypatch.setattr(ext.httpx, "get", lambda *a, **k: response({}, 429))
    assert ext.lookup_opswat("example.com")["status"] == "rate_limited"


def test_missing_credentials_are_unknown(monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", " ")
    monkeypatch.setattr(settings, "opswat_api_key", "")
    assert ext.lookup_otx("example.com")["verdict"] == "unknown"
    assert ext.lookup_opswat("example.com")["verdict"] == "unknown"
