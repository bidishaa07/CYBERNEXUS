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
