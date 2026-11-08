from backend.app.engines import message_intelligence


def test_url_provider_results_are_associated_with_original_indicator(monkeypatch):
    monkeypatch.setattr(message_intelligence, "check_url", lambda url: {"providers": [{"provider": "fixture", "status": "queried", "verdict": "malicious"}], "findings": [{"provider": "fixture"}]})
    result = message_intelligence.analyze_indicators({"urls": ["https://example.com/login"], "emails": [], "phones": []})
    assert result["urls"][0]["indicator"] == "https://example.com/login"
    assert result["urls"][0]["verdict"] == "malicious"
    assert result["urls"][0]["provider_results"][0]["provider"] == "fixture"


def test_email_domain_similarity_is_not_confirmed_fraud(monkeypatch):
    monkeypatch.setattr(message_intelligence, "analyze_domain", lambda domain: {"brand_matches": [{"brand": "amazon", "official_domain": "amazon.com", "similarity_percent": 90, "edit_distance": 1, "manipulation": "substitution"}]})
    monkeypatch.setattr(message_intelligence, "check_url", lambda url: {"providers": [{"provider": "fixture", "status": "queried", "verdict": "no_match"}], "findings": []})
    result = message_intelligence.analyze_indicators({"urls": [], "emails": ["support@amaz0n.com"], "phones": []})
    assert result["emails"][0]["status"] == "COMPLETED"
    assert result["domain_spoofing"][0]["verification_status"] in {"built_in_candidate", "verified_reference"}
    assert result["domain_spoofing"][0]["confidence"] == "low"


def test_phone_metadata_does_not_create_threat_verdict():
    result = message_intelligence.analyze_indicators({"urls": [], "emails": [], "phones": ["+14155552671"]})
    assert result["phones"][0]["verdict"] == "unknown"
    assert result["phones"][0]["status"] == "COMPLETED"
