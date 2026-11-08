"""Safe connectivity checks for configured OTX and MetaDefender credentials."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from backend.app.core.config import settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check(provider: str, key: str, url: str, header: str) -> dict[str, Any]:
    if not key.strip():
        return {"provider": provider, "status": "not_configured", "configured": False, "checked_at": _now(), "verdict": "unknown"}
    try:
        response = httpx.get(url, headers={header: key.strip(), "Accept": "application/json"}, timeout=settings.provider_timeout_seconds, follow_redirects=False)
    except httpx.TimeoutException:
        return {"provider": provider, "status": "timeout", "configured": True, "checked_at": _now(), "verdict": "unknown"}
    except httpx.RequestError as exc:
        return {"provider": provider, "status": "unavailable", "configured": True, "checked_at": _now(), "verdict": "unknown", "error": type(exc).__name__}
    if response.status_code in (401, 403):
        return {"provider": provider, "status": "invalid_credentials", "configured": True, "checked_at": _now(), "verdict": "unknown", "http_status": response.status_code}
    if response.status_code == 429:
        return {"provider": provider, "status": "rate_limited", "configured": True, "checked_at": _now(), "verdict": "unknown", "http_status": 429}
    if 200 <= response.status_code < 300:
        return {"provider": provider, "status": "connected", "configured": True, "checked_at": _now(), "verdict": "available", "http_status": response.status_code}
    return {"provider": provider, "status": "provider_error", "configured": True, "checked_at": _now(), "verdict": "unknown", "http_status": response.status_code}


def status() -> dict[str, Any]:
    return {"providers": [
        _check("AlienVault OTX", settings.otx_api_key, "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1", "X-OTX-API-KEY"),
        _check("OPSWAT MetaDefender Cloud", settings.opswat_api_key, "https://api.metadefender.com/v4/apikey/", "apikey"),
    ], "checked_at": _now(), "note": "Connectivity status only; scan verdicts use separate domain lookups."}


def urlhaus_status() -> dict[str, Any]:
    if not settings.urlhaus_auth_key.strip():
        return {"provider": "URLhaus", "status": "not_configured", "configured": False, "verdict": "unknown", "checked_at": _now()}
    try:
        response = httpx.post(settings.urlhaus_api_url, headers={"Auth-Key": settings.urlhaus_auth_key.strip(), "Accept": "application/json"}, data={"url": "https://example.com"}, timeout=settings.provider_timeout_seconds)
    except httpx.TimeoutException:
        return {"provider": "URLhaus", "status": "timeout", "configured": True, "verdict": "unknown", "checked_at": _now()}
    except httpx.RequestError as exc:
        return {"provider": "URLhaus", "status": "unavailable", "configured": True, "verdict": "unknown", "error": type(exc).__name__, "checked_at": _now()}
    if response.status_code in (401, 403): status_value = "invalid_credentials"
    elif response.status_code == 429: status_value = "rate_limited"
    elif 200 <= response.status_code < 300: status_value = "connected"
    else: status_value = "provider_error"
    return {"provider": "URLhaus", "status": status_value, "configured": True, "verdict": "available" if status_value == "connected" else "unknown", "http_status": response.status_code, "checked_at": _now()}


def _lookup(provider: str, key: str, url: str, header: str, parser) -> dict[str, Any]:
    base = {"provider": provider, "checked_at": _now(), "source": url}
    if not key.strip():
        return {**base, "status": "not_configured", "verdict": "unknown", "reason": "API key not configured"}
    try:
        response = httpx.get(url, headers={header: key.strip(), "Accept": "application/json"}, timeout=settings.provider_timeout_seconds, follow_redirects=False)
    except httpx.TimeoutException:
        return {**base, "status": "timeout", "verdict": "unknown", "reason": "provider request timed out"}
    except httpx.RequestError as exc:
        return {**base, "status": "unavailable", "verdict": "unknown", "reason": type(exc).__name__}
    if response.status_code in (401, 403):
        return {**base, "status": "invalid_credentials", "verdict": "unknown", "http_status": response.status_code}
    if response.status_code == 429:
        return {**base, "status": "rate_limited", "verdict": "unknown", "http_status": 429}
    if response.status_code < 200 or response.status_code >= 300:
        return {**base, "status": "provider_error", "verdict": "unknown", "http_status": response.status_code}
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return {**base, "status": "invalid_response", "verdict": "unknown", "reason": "malformed JSON"}
    if not isinstance(payload, dict):
        return {**base, "status": "invalid_response", "verdict": "unknown", "reason": "unexpected response format"}
    return {**base, "status": "queried", **parser(payload)}


def lookup_otx(domain: str) -> dict[str, Any]:
    def parse(payload: dict[str, Any]) -> dict[str, Any]:
        pulse_info = payload.get("pulse_info") if isinstance(payload.get("pulse_info"), dict) else {}
        count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", []) if isinstance(pulse_info.get("pulses", []), list) else []
        return {"verdict": "suspicious" if count else "no_match", "pulse_count": count,
                "threat_reports": [{"id": p.get("id"), "name": p.get("name"), "created": p.get("created"), "modified": p.get("modified")} for p in pulses[:20] if isinstance(p, dict)],
                "evidence": {"indicator": domain, "pulse_count": count}}
    return _lookup("AlienVault OTX", settings.otx_api_key, f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain, safe='')}/general", "X-OTX-API-KEY", parse)


def lookup_opswat(domain: str) -> dict[str, Any]:
    def parse(payload: dict[str, Any]) -> dict[str, Any]:
        raw = payload.get("lookup_result") or payload.get("verdict") or payload.get("reputation") or payload.get("status")
        normalized = str(raw).lower() if raw is not None else ""
        lookup_results = payload.get("lookup_results") if isinstance(payload.get("lookup_results"), dict) else {}
        detected_by = lookup_results.get("detected_by")
        sources = lookup_results.get("sources") if isinstance(lookup_results.get("sources"), list) else []
        assessments = [str(item.get("assessment", "")).lower() for item in sources if isinstance(item, dict)]
        if any(word in normalized for word in ("malicious", "infected", "phishing")) or any(word in assessment for assessment in assessments for word in ("malicious", "infected", "phishing")):
            verdict = "malicious" if any(word in normalized for word in ("malicious", "infected", "phishing")) else "suspicious"
        elif (isinstance(detected_by, int) and detected_by == 0) or any(assessment in {"clean", "benign", "safe", "trustworthy", "no_threat"} for assessment in assessments):
            verdict = "no_match"
        elif "suspicious" in normalized or any("suspicious" in assessment for assessment in assessments):
            verdict = "suspicious"
        else:
            verdict = "unknown"
        return {"verdict": verdict, "lookup_result": raw, "detected_by": detected_by, "evidence": payload}
    return _lookup("OPSWAT MetaDefender Cloud", settings.opswat_api_key, f"https://api.metadefender.com/v4/domain/{quote(domain, safe='')}", "apikey", parse)
