import json
from backend.app.engines.url_utils import normalize_url
from backend.app.engines.phishing import analyze
from backend.app.engines.network import inspect
from backend.app.engines.threats import check
from backend.app.engines.risk import calculate
from backend.app.engines.dns import inspect_dns
from backend.app.engines.certificate import inspect_certificate
from backend.app.engines.domain_intelligence import collect
from backend.app.engines.redirect_risk import score_redirect_chain, compare_destinations

def _provider_state(item):
    status=str(item.get("status", "unknown")).lower()
    verdict=str(item.get("verdict", "unknown")).lower()
    if status in {"not_configured", "not_configured"}: state="NOT_CONFIGURED"
    elif status in {"invalid_credentials", "rate_limited", "quota_exceeded", "timeout", "unavailable", "network_error", "provider_error", "invalid_response"}: state=status.upper()
    elif verdict in {"malicious", "phishing", "suspicious"}: state="THREAT_DETECTED"
    elif verdict in {"no_match", "clean"}: state="NO_MATCH"
    elif status in {"pending"}: state="PENDING"
    elif status in {"not_supported"}: state="NOT_SUPPORTED"
    elif status in {"configured"}: state="CONFIGURED"
    elif status in {"queried", "available", "complete", "completed"}: state="COMPLETED"
    elif status == "connected": state="CONNECTED"
    else: state="UNKNOWN"
    return {**item, "state":state, "verdict": item.get("verdict", "unknown"), "evidence_available": bool(item.get("evidence") or item.get("matches") or item.get("threat_reports"))}

def _destination_providers(threats, intel):
    providers=[_provider_state(item) for item in threats.get("providers", [])]
    rdap=intel.get("rdap", {})
    providers.append(_provider_state({"provider":"RDAP", "status":"completed" if rdap.get("status")=="available" else rdap.get("status", "unavailable"), "verdict":"no_match" if rdap.get("status")=="available" else "unknown", "evidence":rdap, "checked_at":rdap.get("checked_at"), "source":"RDAP"}))
    infra=intel.get("infrastructure", {})
    ip_records=infra.get("providers", []) if isinstance(infra, dict) else []
    if ip_records:
        for record in ip_records:
            providers.append(_provider_state({"provider":record.get("source", "IP intelligence"), "status":record.get("status", "unknown"), "verdict":"unknown", "evidence":record, "ip":record.get("ip"), "checked_at":record.get("checked_at"), "cache":record.get("cache")}))
    else:
        providers.append(_provider_state({"provider":"IPinfo", "status":"unavailable", "verdict":"unknown", "reason":"No destination IP intelligence available"}))
    unique=[]; seen=set()
    for item in providers:
        key=(item.get("provider"), item.get("ip"), item.get("state"), item.get("verdict"))
        if key not in seen: seen.add(key); unique.append(item)
    return unique

def scan(raw_url: str, db=None):
    url, domain = normalize_url(raw_url)
    phishing = analyze(url, domain); network = inspect(url, domain); threats = check(url)
    dns = inspect_dns(domain); certificate = inspect_certificate(domain, db)
    network["dns"] = dns
    domain_intelligence = collect(url, domain)
    destination_results = {}
    for hop in network.get("http", {}).get("redirects", []):
        destination = hop.get("destination_url")
        destination_domain = hop.get("destination_domain")
        if not destination or not destination_domain or destination_domain in destination_results:
            continue
        try:
            destination_threats = check(destination)
            destination_domain_intel = collect(destination, destination_domain)
            verdicts = {p.get("verdict") for p in destination_threats.get("providers", [])}
            verdict = "malicious" if "malicious" in verdicts or "phishing" in verdicts else "suspicious" if "suspicious" in verdicts else "unknown"
            destination_results[destination_domain] = {"status":"complete", "verdict":verdict, "threat_intelligence":destination_threats, "provider_results":_destination_providers(destination_threats, destination_domain_intel), "brand_matches":destination_domain_intel.get("domain",{}).get("brand_matches",[]), "domain_intelligence":destination_domain_intel}
        except Exception as exc:
            destination_results[destination_domain] = {"status":"unavailable", "verdict":"unknown", "provider_results":[{"provider":"Destination intelligence", "state":"UNAVAILABLE", "status":"unavailable", "verdict":"unknown", "reason":type(exc).__name__, "evidence_available":False}] , "reason":type(exc).__name__}
    redirect_risk = score_redirect_chain(url, network.get("http", {}).get("redirects", []), destination_results)
    network["redirect_analysis"] = {"risk":redirect_risk, "comparison":compare_destinations(url, network.get("http", {}).get("redirects", []), destination_results), "destinations":destination_results}
    precautions = ["Do not enter passwords or payment details until independently verified", "Check the domain spelling and certificate identity", "Treat a valid TLS certificate as transport protection, not proof of a safe website"]
    overall_risk = calculate(phishing, network, threats, domain_intelligence, certificate)
    redirect_score = redirect_risk.get("score", 0)
    if redirect_score:
        overall_risk["score"] = min(100, overall_risk["score"] + min(25, redirect_score // 2))
        overall_risk["level"] = "Critical" if overall_risk["score"] >= 80 else "High" if overall_risk["score"] >= 55 else "Medium" if overall_risk["score"] >= 25 else "Low"
        overall_risk["redirect_influence"] = {"score":redirect_score, "added":min(25, redirect_score // 2), "explanation":"Redirect evidence contributes up to 25 points and is kept separate from the redirect score."}
    return {"url": raw_url, "normalized_url": url, "domain": domain, "phishing": phishing, "domain_intelligence": domain_intelligence, "network": network, "certificate": certificate, "threat_intelligence": threats, "precautions": precautions, "risk": overall_risk}
