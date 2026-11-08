from backend.app.engines.advanced_security import (
    analyze_cache, analyze_cookies, analyze_cors, analyze_cross_origin_policies,
    analyze_mixed_content, analyze_permissions_policy, analyze_response,
)


def test_cookie_samesite_none_requires_secure_and_scope_is_reported():
    findings = analyze_cookies(
        {"set-cookie": [
            "session=abc; SameSite=None; Path=/; Domain=example.test",
            "prefs=dark; SameSite=Lax; Secure; HttpOnly; Path=/settings",
        ]},
        "https://example.test/account",
    )
    assert any(item["check_identifier"] == "cookie_0_samesite_secure" and item["status"] == "FAIL" for item in findings)
    scope = next(item for item in findings if item["check_identifier"] == "cookie_0_scope")
    assert scope["status"] == "WARNING"
    assert any(item["check_identifier"] == "cookie_1_httponly" and item["status"] == "PASS" for item in findings)


def test_cors_context_distinguishes_public_wildcard_from_credentialed_wildcard():
    public = analyze_cors({"access-control-allow-origin": "*"})
    assert public[0]["status"] == "WARNING"
    credentialed = analyze_cors({"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
    assert credentialed[0]["status"] == "FAIL"
    assert "allow_methods" in credentialed[0]["evidence"]


def test_mixed_content_classifies_active_and_passive_resources_without_fetching():
    body = b'<script src=\"http://cdn.test/app.js\"></script><img src=\"http://cdn.test/logo.png\"><link rel=\"stylesheet\" href=\"http://cdn.test/app.css\">'
    findings = analyze_mixed_content(body, "https://example.test/")
    assert {item["evidence"]["type"] for item in findings} == {"active", "passive"}
    assert all(item["status"] == "FAIL" for item in findings)


def test_cache_policy_does_not_flag_non_sensitive_page_and_flags_public_session_response():
    assert analyze_cache({"cache-control": "public, max-age=3600"}, "https://example.test/")[0]["status"] == "NOT_APPLICABLE"
    finding = analyze_cache({"cache-control": "public, max-age=3600", "set-cookie": "sid=x"}, "https://example.test/login")[0]
    assert finding["status"] == "WARNING"
    assert finding["severity"] == "HIGH"


def test_permissions_and_cross_origin_policy_syntax():
    invalid = analyze_permissions_policy({"permissions-policy": "camera=(self), ???"})
    assert invalid[0]["status"] == "FAIL"
    valid = analyze_permissions_policy({"permissions-policy": "camera=(self), microphone=()"})
    assert valid[0]["status"] == "PASS"
    policies = analyze_cross_origin_policies({
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-origin",
    })
    assert all(item["status"] == "PASS" for item in policies)


def test_missing_headers_are_not_reported_as_critical_failures():
    result = analyze_response({}, b"<html><body>public page</body></html>", "https://example.test/")
    assert result["cors_observed"] is False
    assert any(item["status"] == "NOT_APPLICABLE" for item in result["findings"])
    assert not any(item["severity"] == "CRITICAL" for item in result["findings"])
