from email.message import EmailMessage

import pytest

from backend.app.engines import email_analysis


def make_message() -> bytes:
    message = EmailMessage()
    message["From"] = "alerts@example.com"
    message["Reply-To"] = "help@other.example"
    message["Return-Path"] = "bounces@example.com"
    message["To"] = "user@example.net"
    message["Subject"] = "Account notice"
    message["Message-ID"] = "<abc@example.com>"
    message["Received"] = "from mail.example by mx.example; Tue, 01 Jan 2030 00:00:00 +0000"
    message["Authentication-Results"] = "mx.example; spf=pass dkim=fail dmarc=fail"
    message["DKIM-Signature"] = "v=1; d=example.com; s=mail; bh=abc; b=def"
    message.set_content("Please review this message")
    message.add_alternative("<p>Please review this message</p>", subtype="html")
    return message.as_bytes()


def test_parses_headers_multipart_and_authentication(monkeypatch):
    monkeypatch.setattr(email_analysis, "_dns_txt", lambda name: ("FOUND", ["v=spf1 -all"] if not name.startswith("_dmarc") else ["v=DMARC1; p=reject"], None))
    result = email_analysis.analyze_email(make_message(), "notice.eml", "message/rfc822")
    assert result["status"] == "COMPLETED"
    assert result["sender"]["from_email"] == "alerts@example.com"
    assert result["sender"]["reply_to_domain"] == "other.example"
    assert result["mime"]["is_multipart"] is True
    assert set(result["mime"]["body_types"]) == {"text/plain", "text/html"}
    assert all(item["status"] == "UNKNOWN" for item in result["authentication"])
    assert {item["mechanism"]: item["evidence"].get("reported_status") for item in result["authentication"]} == {"SPF": "PASS", "DKIM": "FAIL", "DMARC": "FAIL"}
    assert any(item["type"] == "FROM_REPLY_TO_MISMATCH" for item in result["anomalies"])


def test_missing_authentication_is_unknown_not_clean(monkeypatch):
    monkeypatch.setattr(email_analysis, "_dns_txt", lambda name: ("UNAVAILABLE", [], "timeout"))
    message = EmailMessage(); message["From"] = "sender@example.com"; message.set_content("hello")
    result = email_analysis.analyze_email(message.as_bytes())
    assert all(item["status"] == "UNKNOWN" for item in result["authentication"])
    assert any(item["type"] == "MISSING_AUTHENTICATION_EVIDENCE" for item in result["anomalies"])


def test_oversized_email_rejected():
    with pytest.raises(ValueError, match="email_file_too_large"):
        email_analysis.analyze_email(b"x" * (email_analysis.MAX_EMAIL_BYTES + 1))


def test_invalid_email_rejected():
    with pytest.raises(ValueError, match="invalid_email"):
        email_analysis.analyze_email(b"not a structured message")


def test_dkim_without_signature_is_none():
    result = email_analysis.verify_dkim_signatures(b"From: sender@example.com\n\nhello")
    assert result[0]["status"] == "NONE"


def test_dkim_verification_uses_independent_verifier(monkeypatch):
    class FakeDkim:
        def __init__(self, raw):
            assert raw.endswith(b"preserved-bytes")

        def verify(self, index, dnsfunc):
            assert index == 0
            assert dnsfunc(b"s1._domainkey.example.com") == b"v=DKIM1; k=rsa; p=public-key"
            return True

    monkeypatch.setattr(email_analysis, "dkim", type("DkimModule", (), {"DKIM": FakeDkim, "DKIMException": Exception}))
    monkeypatch.setattr(email_analysis, "_dkim_dns", lambda name: b"v=DKIM1; k=rsa; p=public-key")
    raw = b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1\nFrom: sender@example.com\n\npreserved-bytes"
    result = email_analysis.verify_dkim_signatures(raw)
    assert result[0]["status"] == "PASS"
    assert result[0]["public_key_status"] == "FOUND"


def test_spf_requires_trusted_smtp_context():
    result = email_analysis.evaluate_spf_context({}, "example.com")
    assert result["status"] == "UNKNOWN"


def test_spf_evaluates_mailfrom_and_helo_separately(monkeypatch):
    class SPFModule:
        @staticmethod
        def check2(ip, sender, helo, **kwargs):
            return ("pass", "fixture pass")

    monkeypatch.setattr(email_analysis, "spf", SPFModule)
    result = email_analysis.evaluate_spf_context({"smtp_client_ip": "203.0.113.10", "envelope_mail_from": "bounce@example.com", "helo_hostname": "mail.example.com", "receiving_server": "mx.example.net", "trusted_source": "fixture"}, "example.com")
    assert result["status"] == "PASS"
    assert result["mail_from"]["status"] == "PASS"
    assert result["helo"]["status"] == "PASS"


def test_dmarc_alignment_requires_authenticated_identity():
    result = email_analysis.evaluate_dmarc_alignment("example.com", {"mail_from": {"status": "UNKNOWN"}}, [{"status": "UNKNOWN", "signing_domain": "example.net"}], ["v=DMARC1; p=reject; adkim=s; aspf=s"])
    assert result["status"] == "UNKNOWN"
