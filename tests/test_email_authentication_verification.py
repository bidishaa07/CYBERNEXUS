from types import SimpleNamespace

from backend.app.engines import email_authentication_verification as auth


def dns_fixture(monkeypatch, records):
    def resolve(name, record, lifetime):
        values = records.get(name, [])
        if not values: raise auth.dns.resolver.NXDOMAIN()
        return [SimpleNamespace(strings=[value.encode()]) for value in values]
    monkeypatch.setattr(auth.dns.resolver, "resolve", resolve)
    auth._cache.clear()


def test_spf_and_dmarc_are_independently_inspected(monkeypatch):
    dns_fixture(monkeypatch, {"example.com": ["v=spf1 include:_spf.example.com -all"], "_dmarc.example.com": ["v=DMARC1; p=reject; adkim=s; aspf=s"]})
    result = auth.verify("example.com")
    assert result["spf"]["status"] == "PASS"
    assert result["spf"]["syntax_valid"] is True
    assert result["dmarc"]["status"] == "PASS"
    assert result["dmarc"]["policy"] == "reject"
    assert result["dkim"]["status"] == "UNKNOWN"


def test_missing_dkim_selector_is_unknown_not_pass(monkeypatch):
    dns_fixture(monkeypatch, {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"]})
    result = auth.verify("example.com")
    assert result["dkim"]["status"] == "UNKNOWN"
    assert "selector" in result["dkim"]["error"]


def test_multiple_spf_records_are_a_failure(monkeypatch):
    dns_fixture(monkeypatch, {"example.com": ["v=spf1 -all", "v=spf1 ~all"], "_dmarc.example.com": []})
    result = auth.verify("example.com")
    assert result["spf"]["status"] == "FAIL"
    assert "Multiple SPF" in result["spf"]["error"]


def test_dns_timeout_is_not_reported_as_missing(monkeypatch):
    def timeout(*args, **kwargs): raise auth.dns.exception.Timeout()
    monkeypatch.setattr(auth.dns.resolver, "resolve", timeout)
    auth._cache.clear()
    result = auth.verify("example.com")
    assert result["spf"]["status"] == "UNKNOWN"
    assert result["spf"]["dns_status"] == "UNAVAILABLE"
    assert result["dmarc"]["status"] == "UNKNOWN"


def test_selector_record_is_not_dkim_pass(monkeypatch):
    dns_fixture(monkeypatch, {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"], "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=abc"]})
    result = auth.verify("example.com", selector="s1")
    assert result["dkim"]["status"] == "WARNING"
    assert result["dkim"]["public_key_status"] == "FOUND"
