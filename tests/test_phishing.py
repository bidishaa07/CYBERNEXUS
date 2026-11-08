from backend.app.engines.phishing import analyze

def test_credential_url_has_signal():
    result = analyze("https://secure-paypal.example/login/verify", "secure-paypal.example")
    assert result["score"] > 0
    assert result["evidence"]
