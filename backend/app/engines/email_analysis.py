"""Conservative RFC email parsing and sender/authentication analysis."""
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

import dns.resolver

MAX_EMAIL_BYTES = 10 * 1024 * 1024
SUPPORTED_TYPES = {"message/rfc822", "application/octet-stream", "text/plain", ""}
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _status_from_auth(value: str | None, mechanism: str) -> tuple[str, dict[str, Any]]:
    if not value:
        return "UNKNOWN", {"reason": "No authentication evidence was supplied"}
    match = re.search(rf"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none|neutral)\b", value, re.I)
    if not match:
        return "UNKNOWN", {"reason": f"No {mechanism} result was present in Authentication-Results"}
    reported = match.group(1).upper()
    return "UNKNOWN", {"reported_status": reported, "source": "uploaded Authentication-Results header; not independently trusted"}

def _domain(address: str) -> str | None:
    parsed = parseaddr(address)[1].lower().rstrip(".")
    return parsed.split("@", 1)[1] if "@" in parsed else None

def _dns_txt(name: str) -> tuple[str, list[str], str | None]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=4)
        values = [b"".join(part if isinstance(part, bytes) else str(part).encode() for part in record.strings).decode(errors="replace") for record in answers]
        return "FOUND", values, None
    except dns.resolver.NXDOMAIN:
        return "NOT_FOUND", [], None
    except Exception as exc:
        return "UNAVAILABLE", [], type(exc).__name__

def _parse_received(value: str) -> dict[str, Any]:
    return {"raw": value, "has_from": bool(re.search(r"\bfrom\b", value, re.I)), "has_by": bool(re.search(r"\bby\b", value, re.I)), "has_date": ";" in value}

def analyze_email(raw: bytes, filename: str = "uploaded.eml", content_type: str = "message/rfc822") -> dict[str, Any]:
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("email_file_too_large")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ValueError(f"invalid_email:{type(exc).__name__}") from exc
    if not list(message.raw_items()):
        raise ValueError("invalid_email:no_headers")
    headers: list[dict[str, Any]] = []
    for position, (name, value) in enumerate(message.raw_items()):
        headers.append({"name": name, "value": str(value), "normalized": str(value).strip() if value is not None else "", "position": position})
    from_value = str(message.get("From", "")); reply_to = str(message.get("Reply-To", "")); return_path = str(message.get("Return-Path", "")); sender = str(message.get("Sender", ""))
    sender_email = parseaddr(from_value)[1].lower()
    from_domain = _domain(from_value); reply_domain = _domain(reply_to); return_domain = _domain(return_path); sender_domain = _domain(sender)
    auth_header = message.get("Authentication-Results")
    auth_results = []
    for mechanism in ("spf", "dkim", "dmarc"):
        status, evidence = _status_from_auth(str(auth_header) if auth_header else None, mechanism)
        auth_results.append({"mechanism": mechanism.upper(), "status": status, "domain": from_domain, "source": "uploaded Authentication-Results" if auth_header else "none", "evidence": evidence})
    dkim_headers = [str(value) for name, value in message.raw_items() if name.lower() == "dkim-signature"]
    for signature in dkim_headers:
        selector = re.search(r"(?:^|;)\s*s=([^;\s]+)", signature, re.I)
        signing_domain = re.search(r"(?:^|;)\s*d=([^;\s]+)", signature, re.I)
        item = next((x for x in auth_results if x["mechanism"] == "DKIM"), None)
        if item:
            item["selector"] = selector.group(1) if selector else None; item["domain"] = signing_domain.group(1).lower() if signing_domain else None; item["evidence"]["signature_present"] = True
    spf_state, spf_records, spf_error = _dns_txt(f"{from_domain}" if from_domain else "invalid.invalid") if from_domain else ("UNAVAILABLE", [], "sender_domain_missing")
    dmarc_state, dmarc_records, dmarc_error = _dns_txt(f"_dmarc.{from_domain}") if from_domain else ("UNAVAILABLE", [], "sender_domain_missing")
    auth_results[0]["policy_lookup"] = {"status": spf_state, "records": spf_records, "error": spf_error}
    auth_results[2]["policy_lookup"] = {"status": dmarc_state, "records": dmarc_records, "error": dmarc_error}
    anomalies = []
    if reply_domain and from_domain and reply_domain != from_domain: anomalies.append({"type": "FROM_REPLY_TO_MISMATCH", "severity": "medium", "evidence": f"From domain {from_domain} differs from Reply-To domain {reply_domain}"})
    if return_domain and from_domain and return_domain != from_domain: anomalies.append({"type": "RETURN_PATH_MISMATCH", "severity": "low", "evidence": f"Return-Path domain {return_domain} differs from From domain {from_domain}"})
    if not auth_header and not dkim_headers: anomalies.append({"type": "MISSING_AUTHENTICATION_EVIDENCE", "severity": "medium", "evidence": "No Authentication-Results or DKIM-Signature header was present"})
    if sender_email and not _EMAIL.match(sender_email): anomalies.append({"type": "MALFORMED_SENDER", "severity": "medium", "evidence": "From address does not have a valid normalized mailbox form"})
    received = [_parse_received(str(value)) for name, value in message.raw_items() if name.lower() == "received"]
    if received and any(not item["has_by"] for item in received): anomalies.append({"type": "MALFORMED_RECEIVED_HEADER", "severity": "low", "evidence": "A Received header lacks an expected by clause"})
    date_value = str(message.get("Date", "")); parsed_date = None
    if date_value:
        try: parsed_date = parsedate_to_datetime(date_value).isoformat()
        except (TypeError, ValueError, IndexError): anomalies.append({"type": "INVALID_DATE_HEADER", "severity": "low", "evidence": "Date header could not be parsed"})
    attachments = []
    for part in message.walk():
        if part.is_multipart(): continue
        disposition = part.get_content_disposition()
        if disposition == "attachment" or part.get_filename(): attachments.append({"filename": part.get_filename(), "content_type": part.get_content_type(), "size": len(part.get_payload(decode=True) or b""), "executed": False})
    body_types = sorted({part.get_content_type() for part in message.walk() if not part.is_multipart() and part.get_content_type() in {"text/plain", "text/html"}})
    urls = re.findall(r"https?://[^\s<>\"]+", raw.decode(errors="replace"), re.I)
    return {"status": "COMPLETED", "filename": filename, "content_type": content_type, "headers": headers, "sender": {"from": from_value, "from_email": sender_email, "from_domain": from_domain, "reply_to": reply_to, "reply_to_domain": reply_domain, "return_path": return_path, "return_path_domain": return_domain, "sender": sender, "sender_domain": sender_domain, "to": str(message.get("To", "")), "cc": str(message.get("Cc", "")), "bcc": str(message.get("Bcc", "")), "subject": str(message.get("Subject", "")), "date": date_value, "date_parsed": parsed_date, "message_id": str(message.get("Message-ID", ""))}, "authentication": auth_results, "anomalies": anomalies, "received": received, "mime": {"body_types": body_types, "attachments": attachments, "is_multipart": message.is_multipart()}, "indicators": {"urls": urls, "emails": re.findall(r"\b[^@\s]+@[^@\s]+\.[A-Za-z]{2,}\b", raw.decode(errors="replace")), "phones": re.findall(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)", raw.decode(errors="replace"))}, "privacy": {"attachments_executed": False, "external_resources_downloaded": False, "message_body_persisted": False}, "checked_at": datetime.now(timezone.utc).isoformat()}
