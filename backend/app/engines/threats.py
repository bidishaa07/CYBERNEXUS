import base64
import json
from datetime import datetime, timezone
import httpx
from backend.app.core.config import settings
from backend.app.engines.google_safe_browsing import lookup as lookup_google_safe_browsing
from backend.app.engines.virustotal import lookup_url as lookup_virustotal_url
from backend.app.engines.external_intelligence import lookup_otx, lookup_opswat
from urllib.parse import urlparse

def _provider(name,status,**extra): return {"provider":name,"status":status,"checked_at":datetime.now(timezone.utc).isoformat(),**extra}

def _virustotal(url):
    return lookup_virustotal_url(url)

def check(url: str):
    providers=[]; findings=[]
    google = lookup_google_safe_browsing(url)
    providers.append(google)
    if google.get("verdict") == "malicious":
        findings.extend({"provider":"Google Safe Browsing", "threat_type":match.get("threat_type"), "state":"confirmed", "evidence":match} for match in google.get("matches", []))
    vt=_virustotal(url); providers.append(vt)
    if vt.get('verdict') in {'malicious','suspicious'}: findings.append({"provider":"VirusTotal","state":vt['verdict'],"evidence":vt})
    domain = (urlparse(url).hostname or "").lower().rstrip(".")
    if domain:
        otx = lookup_otx(domain); providers.append(otx)
        if otx.get("verdict") in {"malicious", "suspicious"}:
            findings.append({"provider":"AlienVault OTX", "state":otx["verdict"], "evidence":otx})
        opswat = lookup_opswat(domain); providers.append(opswat)
        if opswat.get("verdict") in {"malicious", "suspicious"}:
            findings.append({"provider":"OPSWAT MetaDefender Cloud", "state":opswat["verdict"], "evidence":opswat})
    try:
        if not settings.urlhaus_auth_key.strip():
            providers.append(_provider("URLhaus","not_configured",verdict="unknown",reason="Auth-Key not configured"))
        else:
            response=httpx.post(settings.urlhaus_api_url,headers={"Auth-Key":settings.urlhaus_auth_key.strip(),"Accept":"application/json"},data={"url":url},timeout=8)
        if settings.urlhaus_auth_key.strip() and response.status_code in (401,403):
            providers.append(_provider("URLhaus","invalid_credentials",verdict="unknown",provider_status=response.status_code))
        elif settings.urlhaus_auth_key.strip() and response.status_code == 429:
            providers.append(_provider("URLhaus","rate_limited",verdict="unknown",provider_status=429))
        elif settings.urlhaus_auth_key.strip() and response.status_code >= 500:
            providers.append(_provider("URLhaus","provider_error",verdict="unknown",provider_status=response.status_code))
        elif settings.urlhaus_auth_key.strip():
            data=response.json(); match=bool(data.get('urlhaus_reference')); providers.append(_provider("URLhaus","queried",verdict="malicious" if match else "no_match",reference=data.get('urlhaus_reference')))
            if match: findings.append({"provider":"URLhaus","state":"confirmed","reference":data.get('urlhaus_reference')})
    except Exception as exc: providers.append(_provider("URLhaus","unavailable",reason=type(exc).__name__))
    if settings.phishtank_api_url:
        try:
            response=httpx.post(settings.phishtank_api_url,data={"url":url,"format":"json"},timeout=8); response.raise_for_status(); data=response.json(); results=data.get('results') or data.get('phish_detail_page') or {}; match=bool(results and (results.get('in_database') or results.get('verified'))); providers.append(_provider("PhishTank","queried",verdict="phishing" if match else "no_match",evidence=results))
            if match: findings.append({"provider":"PhishTank","state":"confirmed","evidence":results})
        except Exception as exc: providers.append(_provider("PhishTank","unavailable",reason=type(exc).__name__))
    else: providers.append(_provider("PhishTank","unavailable",reason="API URL not configured"))
    unique=[]; seen=set()
    for finding in findings:
        key=(finding.get("provider"), finding.get("threat_type"), json.dumps(finding.get("evidence", finding.get("reference", "")), sort_keys=True, default=str))
        if key not in seen:
            seen.add(key); unique.append(finding)
    return {"providers":providers,"findings":unique,"note":"Unavailable providers are not treated as clean."}
