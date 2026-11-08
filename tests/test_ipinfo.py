from types import SimpleNamespace

import httpx

from backend.app.core.config import settings
from backend.app.engines import ipinfo


def response(status=200, payload=None, content_type="application/json"):
    return SimpleNamespace(status_code=status, headers={"content-type": content_type}, json=lambda: payload)


def setup(monkeypatch, token="test-token"):
    monkeypatch.setattr(settings, "ipinfo_token", token)
    monkeypatch.setattr(settings, "ipinfo_cache_ttl_seconds", 3600)
    monkeypatch.setattr(settings, "ipinfo_timeout_seconds", 1)
    ipinfo.clear_cache()


def test_missing_token_is_distinguished(monkeypatch):
    setup(monkeypatch, "")
    result = ipinfo.lookup_ip("8.8.8.8")
    assert result["status"] == "not_configured"


def test_success_ipv4_parses_asn_and_plan_fields(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(ipinfo.httpx, "get", lambda *a, **k: response(payload={
        "ip": "8.8.8.8", "org": "AS15169 Google LLC", "as_domain": "google.com",
        "country": "US", "country_name": "United States", "hosting": True,
    }))
    result = ipinfo.lookup_ip("8.8.8.8")
    assert result["status"] == "queried"
    assert result["asn_number"] == "AS15169"
    assert result["asn_organization"] == "Google LLC"
    assert result["asn_domain"] == "google.com"
    assert result["country"] == "US"
    assert result["hosting"] is True
    assert "privacy" in result["unavailable_fields"]


def test_ipinfo_lite_endpoint_and_response_fields(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(settings, "ipinfo_base_url", "https://api.ipinfo.io/lite")
    requested = []
    monkeypatch.setattr(ipinfo.httpx, "get", lambda url, **k: (requested.append(url) or response(payload={"ip": "8.8.8.8", "asn": "15169", "as_name": "Google LLC", "as_domain": "google.com", "country_code": "US", "country": "United States"})))
    result = ipinfo.lookup_ip("8.8.8.8")
    assert requested == ["https://api.ipinfo.io/lite/8.8.8.8"]
    assert result["asn_number"] == "AS15169"
    assert result["asn_organization"] == "Google LLC"
    assert result["asn_domain"] == "google.com"
    assert result["country_name"] == "United States"


def test_ipv6_and_exact_domain_association(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(ipinfo.socket, "getaddrinfo", lambda *a, **k: [
        (2, 1, 6, "", ("2001:4860:4860::8888", 443, 0, 0)),
        (2, 1, 6, "", ("8.8.8.8", 443, 0, 0)),
    ])
    monkeypatch.setattr(ipinfo.httpx, "get", lambda url, **k: response(payload={"org": "AS1 Example", "country": "US"}))
    result = ipinfo.collect_ip_intelligence("example.com")
    assert {item["ip"] for item in result["providers"]} == {"8.8.8.8", "2001:4860:4860::8888"}
    assert {item["ip"] for item in result["resolved_ips"]} == {"8.8.8.8", "2001:4860:4860::8888"}


def test_freeipapi_fallback_parses_basic_asn_without_fabricating_hosting(monkeypatch):
    setup(monkeypatch, "")
    monkeypatch.setattr(settings, "ip_intelligence_provider", "freeipapi")
    monkeypatch.setattr(ipinfo.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 443, 0, 0))])
    monkeypatch.setattr(ipinfo.httpx, "get", lambda *a, **k: response(payload={"asn": 15169, "asnOrganization": "Google LLC", "countryCode": "US", "countryName": "United States", "isProxy": False}))
    result = ipinfo.collect_ip_intelligence("example.com")
    assert result["status"] == "available"
    assert result["provider"]["name"] == "FreeIPAPI"
    assert result["providers"][0]["asn_number"] == "AS15169"
    assert result["providers"][0]["hosting"] is None


def test_invalid_credentials_timeout_and_rate_limit(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setattr(ipinfo.httpx, "get", lambda *a, **k: response(status=401, payload={}))
    assert ipinfo.lookup_ip("8.8.8.8")["status"] == "invalid_credentials"
    def timeout(*a, **k):
        raise httpx.ReadTimeout("timed out")
    monkeypatch.setattr(ipinfo.httpx, "get", timeout)
    assert ipinfo.lookup_ip("1.1.1.1")["error"] == "timeout"
    monkeypatch.setattr(ipinfo.httpx, "get", lambda *a, **k: response(status=429, payload={}))
    assert ipinfo.lookup_ip("9.9.9.9")["status"] == "rate_limited"
