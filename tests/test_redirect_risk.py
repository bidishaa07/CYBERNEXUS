from backend.app.engines.redirect_risk import score_redirect_chain, compare_destinations

def test_redirect_risk_explains_downgrade_and_malicious_destination():
    hops = [{"sequence": 1, "source_domain": "example.com", "destination_domain": "evil.test", "destination_url": "http://evil.test/login", "status_code": 302, "https_downgrade": True, "analysis_status": "complete"}]
    result = score_redirect_chain("https://example.com", hops, {"evil.test": {"verdict": "malicious"}})
    assert result["score"] >= 65
    assert {item["code"] for item in result["evidence"]} == {"cross_domain", "https_downgrade", "malicious_destination"}
    assert result["level"] == "High"

def test_redirect_comparison_preserves_original_and_final_domains():
    hops = [{"destination_url": "https://login.example.net/path", "destination_domain": "login.example.net"}]
    comparison = compare_destinations("https://example.com", hops)
    assert comparison["original_registered_domain"] == "example.com"
    assert comparison["final_registered_domain"] == "example.net"
    assert comparison["registered_domain_changed"] is True

def test_cross_domain_alone_is_not_malicious():
    hops = [{"source_domain": "a.example.com", "destination_domain": "b.example.com", "status_code": 302, "analysis_status": "complete"}]
    result = score_redirect_chain("https://a.example.com", hops)
    assert result["score"] == 0
    assert result["level"] == "Low"
