import os
import pytest
from backend.app.engines.domain_intelligence import analyze_identity

@pytest.mark.skipif(os.getenv("RUN_LIVE_IDENTITY") != "1", reason="network-dependent identity verification is opt-in")
def test_live_google_identity_assets_are_retrieved_and_decoded():
    result=analyze_identity("https://www.google.com")
    assert result["status"] == "available"
    assert any(item.get("status") == "available" and item.get("format") == "ICO" for item in result["favicon_candidates"])
    assert any(item.get("status") == "available" for item in result["logo_assets"])
