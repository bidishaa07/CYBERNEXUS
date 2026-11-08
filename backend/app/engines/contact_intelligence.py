"""Phone validation/reputation and database-backed email classification."""
import re
import random
import time
from datetime import datetime, timezone
from urllib.parse import quote
import httpx
import dns.resolver
from backend.app.core.config import settings
from backend.app.engines.domain_intelligence import analyze_domain, registered_domain
from backend.app.engines.threats import check as check_url
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder
except ImportError: phonenumbers = None

_cache = {}
def _now(): return datetime.now(timezone.utc).isoformat()

def validate_phone(value):
    base={"indicator":value,"provider":"libphonenumber","checked_at":_now(),"verdict":"unknown","status":"UNKNOWN","risk_score":None,"classification":"UNKNOWN","confidence":"low","evidence":[]}
    if not phonenumbers: return {**base,"status":"UNAVAILABLE","reason":"Phone validation library is unavailable"}
    try:
        parsed=phonenumbers.parse(value,None); valid=phonenumbers.is_valid_number(parsed); possible=phonenumbers.is_possible_number(parsed); number_type=phonenumbers.number_type(parsed)
        type_name={phonenumbers.PhoneNumberType.MOBILE:"MOBILE",phonenumbers.PhoneNumberType.FIXED_LINE:"LANDLINE",phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:"FIXED_OR_MOBILE",phonenumbers.PhoneNumberType.VOIP:"VOIP",phonenumbers.PhoneNumberType.PERSONAL_NUMBER:"PERSONAL",phonenumbers.PhoneNumberType.PAGER:"PAGER"}.get(number_type,"UNKNOWN")
        return {**base,"status":"COMPLETED","normalized":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.E164),"international_format":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.INTERNATIONAL),"national_format":phonenumbers.format_number(parsed,phonenumbers.PhoneNumberFormat.NATIONAL),"country_code":parsed.country_code,"national_number":str(parsed.national_number),"country":geocoder.description_for_number(parsed,"en"),"carrier":carrier.name_for_number(parsed,"en"),"number_type":type_name,"valid":valid,"possible":possible,"evidence":["Numbering metadata only; validity is not abuse reputation."]}
    except Exception as exc: return {**base,"status":"COMPLETED","valid":False,"possible":False,"reason":type(exc).__name__}

def phone_reputation(number):
    if not settings.phone_reputation_api_url.strip(): return {"provider":"Phone abuse reputation","status":"NOT_CONFIGURED","verdict":"unknown","classification":"UNKNOWN","reason":"Phone abuse reputation provider not configured.","checked_at":_now()}
    key=(number,settings.phone_reputation_api_url)
    if key in _cache and _cache[key]["expires"]>datetime.now(timezone.utc).timestamp(): return {**_cache[key]["result"],"cached":True}
    headers={"Accept":"application/json"}; token=settings.phone_reputation_api_key.strip()
    if token: headers[settings.phone_reputation_auth_header]=f"Bearer {token}" if settings.phone_reputation_auth_header.lower()=="authorization" else token
    response = None
    for attempt in range(3):
      try:
        response=httpx.get(settings.phone_reputation_api_url,params={"phone":number},headers=headers,timeout=settings.phone_reputation_timeout_seconds,follow_redirects=False)
        if response.status_code not in (429,) and response.status_code < 500: break
        if attempt < 2: time.sleep(min(2 ** attempt + random.random(), 4))
      except httpx.TimeoutException:
        if attempt == 2: return {"provider":"Phone abuse reputation","status":"TIMEOUT","verdict":"unknown","reason":"Phone reputation could not be verified.","checked_at":_now()}
        time.sleep(min(2 ** attempt + random.random(), 4))
      except httpx.RequestError as exc:
        if attempt == 2: return {"provider":"Phone abuse reputation","status":"UNAVAILABLE","verdict":"unknown","reason":"Phone reputation could not be verified.","error":type(exc).__name__,"checked_at":_now()}
        time.sleep(min(2 ** attempt + random.random(), 4))
    try:
        if response is None: return {"provider":"Phone abuse reputation","status":"UNAVAILABLE","verdict":"unknown","reason":"Phone reputation could not be verified.","checked_at":_now()}
        if response.status_code in (401,403): return {"provider":"Phone abuse reputation","status":"INVALID_CREDENTIALS","verdict":"unknown","reason":"Provider rejected credentials","checked_at":_now()}
        if response.status_code==429: return {"provider":"Phone abuse reputation","status":"RATE_LIMITED","verdict":"unknown","reason":"Provider rate limit reached","checked_at":_now()}
        if response.status_code>=500: return {"provider":"Phone abuse reputation","status":"UNAVAILABLE","verdict":"unknown","reason":"Provider server error","checked_at":_now()}
        if not 200<=response.status_code<300: return {"provider":"Phone abuse reputation","status":"PROVIDER_ERROR","verdict":"unknown","reason":f"HTTP {response.status_code}","checked_at":_now()}
        payload=response.json(); verdict=str(payload.get("verdict") or payload.get("reputation") or "unknown").lower(); verdict="malicious" if verdict in {"fraud","scam","malicious"} else "suspicious" if verdict in {"spam","suspicious","high_risk"} else "clean" if verdict in {"clean","safe","low_risk"} else "unknown"
        result={"provider":"Phone abuse reputation","status":"COMPLETED","verdict":verdict,"confidence":payload.get("confidence"),"abuse_reports":payload.get("abuse_reports"),"evidence":payload,"checked_at":_now()}; _cache[key]={"result":result,"expires":datetime.now(timezone.utc).timestamp()+settings.phone_reputation_cache_ttl_seconds}; return result
    except (ValueError, TypeError) as exc: return {"provider":"Phone abuse reputation","status":"PROVIDER_ERROR","verdict":"unknown","reason":"Provider returned an invalid response.","error":type(exc).__name__,"checked_at":_now()}

def phone_analysis(value):
    validation=validate_phone(value); reputation=phone_reputation(validation.get("normalized",value)) if validation.get("normalized") else {"provider":"Phone abuse reputation","status":"UNKNOWN","verdict":"unknown","reason":"Number could not be normalized","checked_at":_now()}
    score=0; evidence=[]
    if reputation.get("verdict")=="malicious": score=90; evidence.append("Provider reported confirmed abuse or fraud intelligence.")
    elif reputation.get("verdict")=="suspicious": score=60; evidence.append("Provider reported suspicious or spam intelligence.")
    if validation.get("valid") is False: score=max(score,20); evidence.append("Number failed numbering validation.")
    classification="CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=30 else "LOW" if reputation.get("verdict")=="clean" else "UNKNOWN"
    return {**validation,"reputation":reputation,"risk_score":score if reputation.get("verdict") in {"malicious","suspicious","clean"} else None,"classification":classification,"verdict":reputation.get("verdict","unknown"),"evidence":validation.get("evidence",[])+evidence,"confidence":"high" if reputation.get("verdict") in {"malicious","suspicious"} else "low"}

def _txt(name):
    try:
        return [b"".join(part if isinstance(part,bytes) else str(part).encode() for part in item.strings).decode(errors="replace") for item in dns.resolver.resolve(name,"TXT",lifetime=4)]
    except Exception: return []

def email_analysis(address, provider_registry=None):
    domain=address.rsplit("@",1)[-1].lower().rstrip("."); registrable=registered_domain(domain); registry=next((item for item in (provider_registry or []) if item.get("domain")==domain or item.get("domain")==registrable),None)
    custom={item.strip().lower() for item in settings.disposable_email_domains.split(",") if item.strip()}; disposable=bool(registry and str(registry.get("disposable")).lower()=="true") or domain in custom or registrable in custom
    provider_name=registry.get("provider_name") if registry else None; category=registry.get("category") if registry else "UNKNOWN"
    try: mx=[str(x.exchange).rstrip(".") for x in dns.resolver.resolve(domain,"MX",lifetime=4)]; mx_status="PRESENT" if mx else "NONE"
    except Exception: mx=[]; mx_status="UNKNOWN"
    spf=[x for x in _txt(domain) if x.lower().startswith("v=spf1")]; dmarc=[x for x in _txt("_dmarc."+domain) if x.lower().startswith("v=dmarc1")]
    try: threat=check_url("https://"+domain)
    except Exception as exc: threat={"providers":[],"findings":[],"error":type(exc).__name__}
    malicious=any(item.get("verdict") in {"malicious","phishing"} for item in threat.get("providers",[])); score=80 if malicious else 15 if disposable else 0; classification="CRITICAL" if score>=80 else "MEDIUM" if disposable else "LOW" if registry and not malicious else "UNKNOWN"; evidence=[]
    if malicious: evidence.append("Configured threat-intelligence provider reported the email domain.")
    if disposable: evidence.append("Domain is listed as disposable; this is not proof of fraud.")
    return {"indicator":address,"domain":domain,"registered_domain":registrable,"provider_name":provider_name,"provider_category":category,"disposable":disposable,"mx":{"status":mx_status,"records":mx},"spf":{"status":"PRESENT" if spf else "UNKNOWN","records":spf},"dmarc":{"status":"PRESENT" if dmarc else "UNKNOWN","records":dmarc},"domain_threat_intelligence":threat,"risk_score":score if classification!="UNKNOWN" else None,"classification":classification,"verdict":"malicious" if malicious else "unknown","confidence":"high" if malicious else "medium" if disposable else "low","evidence":evidence,"checked_at":_now()}
