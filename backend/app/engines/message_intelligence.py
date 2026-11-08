"""Indicator-only threat intelligence and sender-domain spoofing analysis."""
import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parseaddr
from urllib.parse import urlparse

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier
except ImportError:  # pragma: no cover
    phonenumbers = None

from backend.app.engines.domain_intelligence import analyze_domain, registered_domain
from backend.app.engines.threats import check as check_url
from backend.app.engines.url_utils import normalize_url
from backend.app.engines.contact_intelligence import phone_analysis, email_analysis

def _now(): return datetime.now(timezone.utc).isoformat()

def _domain_from_email(value):
    match = re.search(r"<[^@<>\s]+@([^<>\s>]+)>|\b[^@<>\s]+@([^<>\s>]+)\b", value or "")
    return (match.group(1) or match.group(2)).lower().rstrip(".") if match else None

def _brand_findings(domain, brands):
    result = analyze_domain(domain)
    official = {str(item.get("official_domain", "")).lower().rstrip("."): item for item in (brands or []) if item.get("verification_status") == "verified"}
    for official_domain, item in official.items():
        if domain == official_domain: continue
        candidate = analyze_domain(domain).get("brand_matches", [])
        for finding in candidate:
            if finding.get("official_domain") == official_domain or finding.get("brand", "").lower() == str(item.get("brand_name", "")).lower():
                finding["verification_status"] = "verified_reference"; finding["confidence"] = "medium"; finding["evidence"] = "Similarity to an approved brand-domain record; not proof of maliciousness."
                yield finding
    for finding in result.get("brand_matches", []):
        if not any(existing.get("official_domain") == finding.get("official_domain") and existing.get("brand") == finding.get("brand") for existing in result.get("brand_matches", []) if existing is not finding):
            finding["verification_status"] = "built_in_candidate"; finding["confidence"] = "low"
            yield finding

def _phone(value):
    return phone_analysis(value)

def analyze_indicators(indicators, sender=None, brands=None, email_providers=None):
    sender = sender or {}; urls=[]; emails=[]; phones=[]; spoofing=[]
    for raw in dict.fromkeys(indicators.get("urls", [])):
        try:
            normalized, domain = normalize_url(raw)
            result = check_url(normalized); urls.append({"indicator": raw, "normalized": normalized, "domain": registered_domain(domain), "status": "COMPLETED", "verdict": "malicious" if any(p.get("verdict") in {"malicious", "phishing"} for p in result.get("providers", [])) else "suspicious" if any(p.get("verdict") == "suspicious" for p in result.get("providers", [])) else "unknown", "provider_results": result.get("providers", []), "findings": result.get("findings", []), "checked_at": _now()})
        except Exception as exc: urls.append({"indicator": raw, "status": "UNKNOWN", "verdict": "unknown", "error": type(exc).__name__, "checked_at": _now()})
    for raw in dict.fromkeys(indicators.get("emails", [])):
        domain = _domain_from_email(raw); item={"indicator": raw, "domain": domain, "status": "UNKNOWN", "verdict": "unknown", "checked_at": _now(), "evidence": {}}
        if domain:
            item.update(email_analysis(raw, email_providers)); item["status"] = "COMPLETED"
            item["domain_intelligence"] = analyze_domain(domain)
            try:
                domain_lookup = check_url("https://" + domain)
                item["provider_results"] = domain_lookup.get("providers", [])
                item["provider_findings"] = domain_lookup.get("findings", [])
            except Exception as exc:
                item["provider_results"] = [{"provider": "Domain threat intelligence", "status": "UNAVAILABLE", "verdict": "unknown", "error": type(exc).__name__, "checked_at": _now()}]
            item["provider_results"].append({"provider": "Domain similarity", "status": "COMPLETED", "verdict": "suspicious" if item["domain_intelligence"].get("brand_matches") else "unknown", "checked_at": item["checked_at"], "evidence": item["domain_intelligence"].get("brand_matches", [])})
            spoofing.extend({**finding, "observed_domain": domain} for finding in _brand_findings(domain, brands))
        emails.append(item)
    for raw in dict.fromkeys(indicators.get("phones", [])): phones.append(_phone(raw))
    from_domain = _domain_from_email(sender.get("from", "")); reply_domain = _domain_from_email(sender.get("reply_to", ""))
    if from_domain and reply_domain and registered_domain(from_domain) != registered_domain(reply_domain): spoofing.append({"brand": None, "observed_domain": reply_domain, "official_domain": from_domain, "similarity": None, "edit_distance": None, "technique": "sender_reply_to_domain_mismatch", "confidence": "medium", "verification_status": "unverified", "evidence": "Reply-To registered domain differs from visible From registered domain."})
    display_name = parseaddr(sender.get("from", ""))[0].casefold()
    for brand, official in (("amazon", "amazon.com"), ("paypal", "paypal.com"), ("google", "google.com"), ("microsoft", "microsoft.com"), ("apple", "apple.com"), ("facebook", "facebook.com"), ("instagram", "instagram.com"), ("netflix", "netflix.com")):
        if brand in display_name and from_domain and registered_domain(from_domain) != official: spoofing.append({"brand": brand, "observed_domain": from_domain, "official_domain": official, "similarity": None, "edit_distance": None, "technique": "display_name_domain_mismatch", "confidence": "medium", "verification_status": "unverified", "evidence": f"Display name mentions {brand}, but the sender domain is not the verified official domain."})
    return {"urls": urls, "emails": emails, "phones": phones, "domain_spoofing": spoofing, "checked_at": _now(), "note": "Indicator intelligence is evidence-based; UNKNOWN and provider failures are not clean results."}
