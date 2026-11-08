"""Explainable risk scoring for the observed HTTP redirect chain."""
from urllib.parse import urlparse
from backend.app.engines.domain_intelligence import registered_domain

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

def _level(score):
    return "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 25 else "Low"

def score_redirect_chain(original_url, hops, destination_results=None):
    destination_results = destination_results or {}
    original_domain = (urlparse(original_url).hostname or "").lower().rstrip(".")
    original_registered = registered_domain(original_domain) if original_domain else ""
    evidence, contributions, missing = [], [], []
    score = 0

    def add(points, code, message, confidence="medium"):
        nonlocal score
        score += points
        item = {"code": code, "message": message, "points": points, "confidence": confidence}
        evidence.append(item); contributions.append(item)

    for hop in hops:
        source = hop.get("source_domain", "")
        dest = hop.get("destination_domain", "")
        if source and dest and registered_domain(source) != registered_domain(dest):
            add(8, "cross_domain", f"Redirect changes registered domain from {registered_domain(source)} to {registered_domain(dest)}", "medium")
        if hop.get("https_downgrade"):
            add(20, "https_downgrade", "HTTPS redirect destination downgrades to HTTP", "high")
        if hop.get("status_code") not in REDIRECT_STATUSES:
            continue
        result = destination_results.get(dest) or {}
        verdict = result.get("verdict")
        if verdict in {"malicious", "phishing"}:
            add(45, "malicious_destination", f"Destination {dest} has a confirmed threat match", "high")
        elif verdict == "suspicious":
            add(25, "suspicious_destination", f"Destination {dest} has suspicious reputation evidence", "medium")
        if result.get("brand_matches"):
            add(20, "brand_impersonation", f"Destination {dest} resembles a verified brand domain", "medium")
        if result.get("status") in {"unavailable", "not_configured"}:
            missing.append({"domain": dest, "reason": "Destination intelligence unavailable"})

    if len(hops) >= 4:
        add(10, "excessive_depth", f"Redirect chain contains {len(hops)} observed hops", "medium")
    if not hops:
        return {"score": 0, "level": "Informational", "confidence": "high", "evidence": [], "contributions": [], "missing_intelligence": [], "complete": True, "summary": "No HTTP redirects were observed."}
    if not evidence and missing:
        confidence = "low"
    elif any(x["confidence"] == "high" for x in evidence):
        confidence = "high"
    else:
        confidence = "medium"
    return {"score": min(score, 100), "level": _level(min(score, 100)), "confidence": confidence, "evidence": evidence, "contributions": contributions, "missing_intelligence": missing, "complete": all(h.get("analysis_status") == "complete" for h in hops), "summary": "Redirect risk is based on observed hop relationships and available destination evidence."}

def compare_destinations(original_url, hops, destination_results=None):
    original = (urlparse(original_url).hostname or "").lower().rstrip(".")
    final = hops[-1].get("destination_url") if hops else original_url
    final_domain = (urlparse(final).hostname or "").lower().rstrip(".")
    return {"original_domain": original, "original_registered_domain": registered_domain(original) if original else "", "final_domain": final_domain, "final_registered_domain": registered_domain(final_domain) if final_domain else "", "registered_domain_changed": registered_domain(original) != registered_domain(final_domain), "destination_count": len({h.get('destination_domain') for h in hops if h.get('destination_domain')}), "destination_results": destination_results or {}}
