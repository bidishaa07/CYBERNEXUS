"""VirusTotal API v3 adapter.

Ordinary scans only look up existing reports. URL submission is explicit and
requires caller confirmation because public VirusTotal submissions may expose
the submitted URL to the service and its community.
"""
from __future__ import annotations

import base64
import ipaddress
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.app.core.config import settings
from backend.app.engines.url_utils import normalize_url

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(status: str, **extra: Any) -> dict[str, Any]:
    return {"provider": "VirusTotal", "status": status, "checked_at": _timestamp(), **extra}


def _key() -> str:
    return settings.virustotal_api_key.strip()


def url_identifier(url: str) -> str:
    """Return the documented base64url-without-padding VT URL identifier."""
    normalized, _ = normalize_url(url)
    return base64.urlsafe_b64encode(normalized.encode()).decode().rstrip("=")


def _headers() -> dict[str, str]:
    return {"x-apikey": _key(), "Accept": "application/json"}


def _error(response: httpx.Response) -> tuple[str, str]:
    message = "provider_http_error"
    try:
        payload = response.json()
        message = str(payload.get("error", {}).get("message") or message)
    except (ValueError, TypeError):
        pass
    lower = message.lower()
    if response.status_code == 401:
        return "invalid_credentials", message
    if response.status_code == 403 and ("quota" in lower or "limit" in lower):
        return "quota_exceeded", message
    if response.status_code == 403:
        return "forbidden", message
    if response.status_code == 404:
        return "not_found", message
    if response.status_code == 429:
        return "rate_limited", message
    if response.status_code >= 500:
        return "provider_error", message
    return "error", message


def _request(method: str, path: str, **kwargs: Any) -> tuple[httpx.Response | None, dict[str, Any] | None]:
    attempts = max(1, settings.virustotal_max_retries + 1)
    endpoint = f"{settings.virustotal_base_url.rstrip('/')}/{path.lstrip('/')}"
    for attempt in range(attempts):
        try:
            response = (httpx.get if method == "GET" else httpx.post)(
                endpoint, headers=_headers(), timeout=settings.virustotal_timeout_seconds,
                follow_redirects=False, **kwargs)
        except httpx.TimeoutException:
            if attempt + 1 < attempts:
                time.sleep(settings.virustotal_retry_backoff_seconds * (2 ** attempt)); continue
            return None, _result("timeout", verdict="unknown", reason="provider request timed out")
        except httpx.RequestError as exc:
            if attempt + 1 < attempts:
                time.sleep(settings.virustotal_retry_backoff_seconds * (2 ** attempt)); continue
            return None, _result("unavailable", verdict="unknown", reason=type(exc).__name__)
        if response.status_code >= 500 or response.status_code in (408, 429):
            if attempt + 1 < attempts:
                time.sleep(settings.virustotal_retry_backoff_seconds * (2 ** attempt)); continue
        return response, None
    return None, _result("unavailable", verdict="unknown", reason="provider retries exhausted")


def _json(response: httpx.Response) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        payload = response.json()
    except (ValueError, TypeError):
        return None, _result("invalid_response", verdict="unknown", reason="malformed JSON")
    if not isinstance(payload, dict):
        return None, _result("invalid_response", verdict="unknown", reason="unexpected response format")
    return payload, None


def _parse_report(payload: dict[str, Any], object_type: str = "url") -> dict[str, Any]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return _result("invalid_response", verdict="unknown", reason="missing data object")
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        return _result("invalid_response", verdict="unknown", reason="missing attributes object")
    stats = attrs.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        return _result("invalid_response", verdict="unknown", reason="invalid analysis statistics")
    counts = {name: int(stats.get(name, 0) or 0) for name in ("malicious", "suspicious", "harmless", "undetected")}
    total = sum(counts.values())
    verdict = "malicious" if counts["malicious"] else "suspicious" if counts["suspicious"] else "no_detection" if total else "unknown"
    results = attrs.get("last_analysis_results") or {}
    engines = []
    if isinstance(results, dict):
        for engine, item in results.items():
            if isinstance(item, dict):
                engines.append({"engine": engine, "category": item.get("category"), "result": item.get("result"), "method": item.get("method")})
    categories = attrs.get("categories") or {}
    return _result("queried", object_type=object_type, verdict=verdict, detection_stats=counts,
                   total_engines=total, malicious_detections=counts["malicious"],
                   suspicious_detections=counts["suspicious"], harmless_detections=counts["harmless"],
                   undetected_results=counts["undetected"], engines=engines,
                   threat_categories=categories, community_reputation=attrs.get("reputation"),
                   last_analysis_date=attrs.get("last_analysis_date"), analysis_status=attrs.get("status"),
                   object_id=data.get("id"), source="VirusTotal API v3")


def _lookup_path(path: str, object_type: str) -> dict[str, Any]:
    if not _key():
        return _result("not_configured", verdict="unknown", reason="API key not configured")
    with _cache_lock:
        cached = _cache.get(path)
        if cached and time.monotonic() - cached[0] < settings.virustotal_cache_ttl_seconds:
            result = dict(cached[1]); result["cache"] = "hit"; return result
    response, failure = _request("GET", path)
    if failure: return failure
    assert response is not None
    if response.status_code != 200:
        status, reason = _error(response)
        return _result(status, verdict="unknown", reason=reason, http_status=response.status_code)
    payload, failure = _json(response)
    if failure: return failure
    result = _parse_report(payload or {}, object_type)
    if result.get("status") == "queried":
        with _cache_lock: _cache[path] = (time.monotonic(), result)
    return result


def lookup_url(url: str) -> dict[str, Any]:
    try:
        identifier = url_identifier(url)
    except ValueError as exc:
        return _result("invalid_input", verdict="unknown", reason=str(exc))
    return _lookup_path(f"urls/{identifier}", "url")


def lookup_domain(domain: str) -> dict[str, Any]:
    return _lookup_path(f"domains/{domain.strip().lower().rstrip('.')}", "domain")


def lookup_ip(address: str) -> dict[str, Any]:
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return _result("invalid_input", verdict="unknown", reason="invalid IP address")
    return _lookup_path(f"ip_addresses/{address}", "ip")


def submit_url(url: str, confirm_public_submission: bool) -> dict[str, Any]:
    if not confirm_public_submission:
        return _result("consent_required", verdict="unknown", reason="Explicit public-submission confirmation is required")
    if not _key():
        return _result("not_configured", verdict="unknown", reason="API key not configured")
    try:
        normalized, _ = normalize_url(url)
    except ValueError as exc:
        return _result("invalid_input", verdict="unknown", reason=str(exc))
    response, failure = _request("POST", "urls", data={"url": normalized})
    if failure: return failure
    assert response is not None
    if response.status_code not in (200, 201):
        status, reason = _error(response)
        return _result(status, verdict="unknown", reason=reason, http_status=response.status_code)
    payload, failure = _json(response)
    if failure: return failure
    data = (payload or {}).get("data", {})
    return _result("submitted", verdict="unknown", analysis_id=data.get("id"), analysis_status="queued", source="VirusTotal API v3")


def poll_analysis(analysis_id: str) -> dict[str, Any]:
    if not _key(): return _result("not_configured", verdict="unknown", reason="API key not configured")
    response, failure = _request("GET", f"analyses/{analysis_id}")
    if failure: return failure
    assert response is not None
    if response.status_code != 200:
        status, reason = _error(response)
        return _result(status, verdict="unknown", reason=reason, http_status=response.status_code)
    payload, failure = _json(response)
    if failure: return failure
    data = (payload or {}).get("data", {})
    attrs = data.get("attributes", {}) if isinstance(data, dict) else {}
    status = attrs.get("status", "unknown") if isinstance(attrs, dict) else "unknown"
    return _result("completed" if status == "completed" else "pending", verdict="unknown", analysis_id=analysis_id, analysis_status=status, source="VirusTotal API v3")


def configuration_status() -> dict[str, Any]:
    return {"provider": "VirusTotal", "api_version": "v3", "base_url": settings.virustotal_base_url,
            "api_key_configured": bool(_key()), "provider_initialized": True,
            "connection_status": "CONFIGURED_NOT_TESTED" if _key() else "NOT_CONFIGURED", "last_checked": None}
