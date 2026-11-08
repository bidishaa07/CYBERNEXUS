"""Independent DNS-backed SPF/DMARC and selector-aware DKIM verification.

Policy inspection is independent from SMTP authentication. A DNS record is
never reported as a DKIM signature PASS; PASS requires genuine message bytes.
"""
import re
from datetime import datetime, timezone
from typing import Any

import dns.resolver

from backend.app.core.config import settings
from backend.app.engines.email_analysis import verify_dkim_signatures

_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _txt(name: str) -> dict[str, Any]:
    key = ("TXT", name.lower().rstrip("."))
    cached = _cache.get(key)
    now = datetime.now(timezone.utc).timestamp()
    if cached and cached[0] > now:
        return {**cached[1], "cached": True}
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=settings.dns_timeout_seconds)
        values = [b"".join(part if isinstance(part, bytes) else str(part).encode() for part in item.strings).decode(errors="replace") for item in answers]
        result = {"status": "FOUND" if values else "NOT_FOUND", "records": values, "checked_at": _now()}
    except dns.resolver.NXDOMAIN:
        result = {"status": "NOT_FOUND", "records": [], "checked_at": _now()}
    except dns.resolver.NoAnswer:
        result = {"status": "NOT_FOUND", "records": [], "checked_at": _now()}
    except Exception as exc:
        result = {"status": "UNAVAILABLE", "records": [], "error": type(exc).__name__, "checked_at": _now()}
    _cache[key] = (now + settings.dns_cache_ttl_seconds, result)
    return result


def _spf(domain: str) -> dict[str, Any]:
    lookup = _txt(domain)
    records = [x for x in lookup["records"] if x.lower().startswith("v=spf1")]
    result: dict[str, Any] = {"domain": domain, "record": records[0] if len(records) == 1 else None, "records": records, "presence": "PRESENT" if records else "MISSING", "status": "UNKNOWN", "syntax_valid": False, "warnings": [], "checked_at": lookup["checked_at"], "dns_status": lookup["status"], "evidence": {"source": "DNS TXT", "cached": lookup.get("cached", False)}}
    if lookup["status"] == "UNAVAILABLE":
        result.update(status="UNKNOWN", error="DNS resolution failed; record presence is unknown")
        return result
    if len(records) > 1:
        result.update(status="FAIL", error="Multiple SPF records were published", warnings=["multiple_spf_records"])
        return result
    if not records:
        result["status"] = "WARNING" if lookup["status"] == "NOT_FOUND" else "UNKNOWN"
        return result
    tokens = records[0].split()
    mechanisms = [x for x in tokens[1:] if not x.startswith("v=")]
    bad = [x for x in mechanisms if not re.match(r"^[+?~-]?(all|include:[^\s]+|a(?::[^\s]+)?(?:/[0-9]+)?|mx(?::[^\s]+)?(?:/[0-9]+)?|ip4:[^\s]+|ip6:[^\s]+|exists:[^\s]+|redirect=[^\s]+|exp=[^\s]+|ptr(?::[^\s]+)?)$", x, re.I)]
    dns_mechanisms = [x for x in mechanisms if re.match(r"^[+?~-]?(include:|a(?:[:/]|$)|mx(?:[:/]|$)|exists:|redirect=|ptr(?:[:]|$))", x, re.I)]
    result["syntax_valid"] = not bad
    result["mechanisms"] = mechanisms
    result["dns_lookup_mechanism_count"] = len(dns_mechanisms)
    if bad: result["warnings"].append("invalid_mechanism")
    if len(dns_mechanisms) > 10: result["warnings"].append("dns_lookup_limit_exceeded")
    if any(x.lower() in {"+all", "all"} for x in mechanisms): result["warnings"].append("permissive_all")
    result["status"] = "PASS" if result["syntax_valid"] and not result["warnings"] else "WARNING" if result["syntax_valid"] else "FAIL"
    return result


def _dmarc(domain: str) -> dict[str, Any]:
    lookup = _txt("_dmarc." + domain)
    records = [x for x in lookup["records"] if x.lower().startswith("v=dmarc1")]
    result: dict[str, Any] = {"domain": domain, "record": records[0] if len(records) == 1 else None, "records": records, "presence": "PRESENT" if records else "MISSING", "status": "UNKNOWN", "syntax_valid": False, "policy": None, "subdomain_policy": None, "alignment": {}, "warnings": [], "checked_at": lookup["checked_at"], "dns_status": lookup["status"], "evidence": {"source": "DNS TXT", "cached": lookup.get("cached", False)}}
    if lookup["status"] == "UNAVAILABLE":
        result["error"] = "DNS resolution failed; DMARC presence is unknown"; return result
    if len(records) > 1:
        result.update(status="FAIL", error="Multiple DMARC records were published"); return result
    if not records:
        result["status"] = "WARNING" if lookup["status"] == "NOT_FOUND" else "UNKNOWN"; return result
    tags = {key.lower(): value for key, value in re.findall(r"(?:^|;)\s*([a-z][a-z0-9]*)=([^;\s]+)", records[0], re.I)}
    result["policy"] = tags.get("p")
    result["subdomain_policy"] = tags.get("sp")
    result["alignment"] = {"aspf": tags.get("aspf", "r"), "adkim": tags.get("adkim", "r")}
    if tags.get("p", "").lower() not in {"none", "quarantine", "reject"}: result["warnings"].append("invalid_policy")
    if tags.get("p", "").lower() == "none": result["warnings"].append("monitoring_only_policy")
    result["syntax_valid"] = not any(x == "invalid_policy" for x in result["warnings"])
    result["status"] = "PASS" if result["syntax_valid"] and not result["warnings"] else "WARNING" if result["syntax_valid"] else "FAIL"
    return result


def verify(domain: str, selector: str | None = None, raw_message: bytes | None = None) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    dkim_result: dict[str, Any]
    if raw_message:
        dkim_result = {"status": "COMPLETED", "signatures": verify_dkim_signatures(raw_message), "source": "independent cryptographic verification", "checked_at": _now()}
    elif selector:
        key = _txt(f"{selector}._domainkey.{domain}")
        record = key["records"][0] if key["records"] else None
        dkim_result = {"status": "WARNING" if record else "UNKNOWN", "selector": selector, "record": record, "public_key_status": "FOUND" if record else key["status"], "source": "DKIM DNS selector inspection", "checked_at": key["checked_at"], "error": None if record else "Selector public key is unavailable"}
    else:
        dkim_result = {"status": "UNKNOWN", "source": "DKIM verification", "error": "DKIM selector or trusted message evidence unavailable", "checked_at": _now()}
    return {"domain": domain, "spf": _spf(domain), "dmarc": _dmarc(domain), "dkim": dkim_result, "checked_at": _now(), "note": "DNS policy presence is not message authentication; missing or unavailable data is not clean."}
