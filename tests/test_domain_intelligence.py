from backend.app.engines.domain_intelligence import analyze_domain


def match(domain):
    return analyze_domain(domain)["brand_matches"]


def test_digit_substitution_is_detected():
    result = match("amaz0n.com")
    assert result and result[0]["brand"] == "amazon"
    assert result[0]["manipulation"] == "homoglyph or lookalike substitution"
    assert result[0]["edit_distance"] == 1


def test_insertion_deletion_and_transposition_are_detected():
    assert match("paypall.com")[0]["manipulation"] == "character insertion"
    assert match("paypa.com")[0]["manipulation"] == "character deletion"
    assert match("goolge.com")[0]["manipulation"] == "character transposition"


def test_tld_variation_and_brand_subdomain_are_detected():
    assert match("amazon.net")[0]["manipulation"] == "TLD variation"
    indicators = analyze_domain("amazon-login.example.com")["indicators"]
    assert any(item["type"] == "impersonating_subdomain" for item in indicators)


def test_idn_is_flagged_without_claiming_ownership():
    result = analyze_domain("xn--pple-43d.com")
    assert any(item["type"] == "homograph" for item in result["indicators"])
    assert result["ownership"]["status"] == "unknown"
