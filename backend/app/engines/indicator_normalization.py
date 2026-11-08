"""Canonical, conservative indicator normalization for correlation.

Normalization creates stable lookup keys; it does not assert that two indicators
belong to the same person, organization, or campaign.
"""
import hashlib
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

INDICATOR_TYPES = {
    "DOMAIN", "IP_ADDRESS", "ASN", "NAMESERVER", "CERTIFICATE_FINGERPRINT",
    "FAVICON_HASH", "CONTENT_FINGERPRINT", "PAYMENT_DESTINATION", "URL",
    "EMAIL_ADDRESS", "PHONE_NUMBER", "MESSAGE_IDENTIFIER",
}

def _text(value):
    if value is None:
        raise ValueError("indicator value is required")
    value = str(value).strip()
    if not value:
        raise ValueError("indicator value is empty")
    return value

def normalize_domain(value):
    value = _text(value).rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid domain") from exc

def normalize_ip(value):
    try:
        return ipaddress.ip_address(_text(value)).compressed
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc

def normalize_asn(value):
    match = re.fullmatch(r"AS?\s*(\d+)", _text(value), re.IGNORECASE)
    if not match:
        raise ValueError("invalid ASN")
    return f"AS{int(match.group(1))}"

def normalize_nameserver(value):
    return normalize_domain(value)

def normalize_fingerprint(value):
    result = re.sub(r"[^0-9a-f]", "", _text(value).lower())
    if not result or len(result) % 2:
        raise ValueError("invalid certificate fingerprint")
    return result

def normalize_hash(value):
    value = _text(value).lower().replace(" ", "")
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError("hash must be hexadecimal")
    return value

def normalize_url(value):
    parsed = urlsplit(_text(value))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must have an HTTP or HTTPS scheme and hostname")
    host = normalize_domain(parsed.hostname)
    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))

def normalize_email(value):
    value = _text(value)
    if value.count("@") != 1:
        raise ValueError("invalid email address")
    local, domain = value.rsplit("@", 1)
    if not local or not domain:
        raise ValueError("invalid email address")
    return f"{local}@{normalize_domain(domain)}"

def normalize_phone(value):
    return re.sub(r"[^0-9+]", "", _text(value))

def normalize_message_id(value):
    return _text(value).strip("<>").lower()

def normalize_payment_destination(value):
    """Conservative payment normalization; type prefixes prevent collisions."""
    value = _text(value)
    if ":" not in value:
        raise ValueError("payment destination must include a type prefix")
    kind, destination = value.split(":", 1)
    kind, destination = kind.strip().lower(), destination.strip()
    if not kind or not destination:
        raise ValueError("invalid payment destination")
    return f"{kind}:{destination}"

def normalize_indicator(indicator_type, value):
    kind = _text(indicator_type).upper()
    if kind not in INDICATOR_TYPES:
        raise ValueError(f"unsupported indicator type: {kind}")
    fn = {
        "DOMAIN": normalize_domain, "NAMESERVER": normalize_nameserver,
        "IP_ADDRESS": normalize_ip, "ASN": normalize_asn,
        "CERTIFICATE_FINGERPRINT": normalize_fingerprint,
        "FAVICON_HASH": normalize_hash, "CONTENT_FINGERPRINT": normalize_hash,
        "URL": normalize_url, "EMAIL_ADDRESS": normalize_email,
        "PHONE_NUMBER": normalize_phone, "MESSAGE_IDENTIFIER": normalize_message_id,
        "PAYMENT_DESTINATION": normalize_payment_destination,
    }.get(kind)
    return kind, fn(value)

def stable_identifier(indicator_type, normalized_value):
    kind, value = normalize_indicator(indicator_type, normalized_value)
    return f"{kind.lower()}:{hashlib.sha256(value.encode()).hexdigest()}"
