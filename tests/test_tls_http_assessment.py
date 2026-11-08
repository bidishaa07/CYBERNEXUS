import backend.app.engines.tls_http_assessment as tls_http
from backend.app.engines.tls_http_assessment import (
    analyze_disclosure, analyze_hsts, analyze_redirect_chain, analyze_tls_report,
)


def test_hsts_quality_and_preload_status_is_evidence_based(monkeypatch):
    monkeypatch.setattr(tls_http, "check_hsts_preload", lambda domain: {"status": "PRELOADED", "response": {"status": "preloaded"}})
    result = analyze_hsts(
        {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"},
        "https://example.test/",
        preload_status=tls_http.check_hsts_preload("example.test"),
    )
    assert result["quality"] == "STRONG"
    assert result["details"]["preload_eligible"] is True
    assert result["details"]["preload_status"] == "PRELOADED"
    assert "preload list" in result["finding"]["limitation"]


def test_hsts_invalid_duplicate_and_missing_states():
    invalid = analyze_hsts({"strict-transport-security": "max-age=abc; max-age=10"}, "https://example.test/")
    assert invalid["quality"] == "MISCONFIGURED"
    assert invalid["finding"]["status"] == "FAIL"
    missing = analyze_hsts({}, "https://example.test/")
    assert missing["quality"] == "MISSING"
    assert missing["finding"]["status"] == "WARNING"


def test_hsts_http_is_not_applicable():
    result = analyze_hsts({"strict-transport-security": "max-age=31536000"}, "http://example.test/")
    assert result["quality"] == "UNKNOWN"
    assert result["finding"]["status"] == "UNKNOWN"


def test_redirect_report_identifies_downgrade_loop_and_cross_domain_without_malicious_label():
    result = analyze_redirect_chain(
        "https://example.test/",
        {"final_url": "http://other.test/", "complete": False,
         "redirects": [{"sequence": 1, "source_url": "https://example.test/",
                        "destination_url": "http://other.test/", "source_domain": "example.test",
                        "destination_domain": "other.test", "status_code": 302,
                        "https_downgrade": True, "analysis_status": "complete"}],
         "unavailable": ["Redirect loop detected"]},
        max_hops=3,
    )
    codes = {item["check_identifier"] for item in result["findings"]}
    assert "redirect_1_https_downgrade" in codes
    assert "redirect_1_domain_change" in codes
    assert "redirect_loop" in codes
    assert result["report"]["loop_detected"] is True


def test_open_redirect_is_passive_indicator_only():
    result = analyze_redirect_chain(
        "https://example.test/login?next=https%3A%2F%2Fother.test",
        {"final_url": "https://other.test/", "complete": True,
         "redirects": [{"sequence": 1, "source_url": "https://example.test/login?next=https%3A%2F%2Fother.test",
                        "destination_url": "https://other.test/", "source_domain": "example.test",
                        "destination_domain": "other.test", "status_code": 302,
                        "https_downgrade": False, "analysis_status": "complete"}]},
    )
    indicator = next(item for item in result["findings"] if "open_redirect" in item["check_identifier"])
    assert indicator["status"] == "WARNING"
    assert "unconfirmed" in indicator["limitation"]
    assert result["report"]["open_redirect_verification"]["status"] == "INDICATOR_ONLY"


def test_disclosure_is_warning_only_and_does_not_claim_cve(monkeypatch):
    monkeypatch.setattr(tls_http, "lookup_disclosure_advisories", lambda details: {"status": "NO_MATCHES", "matches": []})
    result = analyze_disclosure({"server": "nginx/1.24.0", "x-powered-by": "Example/2.1"})
    assert result["finding"]["status"] == "WARNING"
    assert "exploitation" in result["finding"]["limitation"]


def test_disclosure_nvd_correlation_is_cautious_and_parses_exact_version_evidence(monkeypatch):
    class Response:
        status_code = 200
        def json(self):
            return {"vulnerabilities": [{"cve": {
                "id": "CVE-TEST-0001", "published": "2024-01-01",
                "descriptions": [{"value": "nginx 1.24.0 advisory text"}]}}]}
    monkeypatch.setattr(tls_http.httpx, "get", lambda *args, **kwargs: Response())
    tls_http.lookup_disclosure_advisories.cache_clear()
    result = tls_http.lookup_disclosure_advisories((("server", "nginx/1.24.0"),))
    assert result["status"] == "MATCHES"
    assert result["matches"][0]["id"] == "CVE-TEST-0001"


def test_tls_report_preserves_unknown_validation_and_explicit_san_failure():
    result = analyze_tls_report(
        "example.test",
        {"status": "UNAVAILABLE", "validation": {"status": "UNKNOWN"},
         "certificate": {}, "tls_configuration": {"overall_grade": "UNKNOWN",
             "san_validation": {"status": "MISMATCH", "requested_hostname": "example.test"}}},
    )
    statuses = {item["check_identifier"]: item["status"] for item in result["findings"]}
    assert statuses["tls_certificate_validation"] == "UNKNOWN"
    assert statuses["tls_hostname_san"] == "FAIL"
    assert statuses["tls_configuration_grade"] == "UNKNOWN"
    assert result["status"] == "PARTIAL"
