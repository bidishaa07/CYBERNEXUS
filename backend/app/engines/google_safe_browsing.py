"""Google Safe Browsing API v4 Lookup adapter.

This module intentionally does not use the Google Web Risk API. Safe Browsing
v4 and Web Risk have different service terms, credentials, endpoints, and
response schemas.
"""
from __future__ import annotations

import time
import threading
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.app.core.config import settings

THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
TEST_URL = "https://testsafebrowsing.appspot.com/s/malware.html"
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_status_cache: tuple[float, dict[str, Any]] | None = None
_cache_lock = threading.Lock()


def clear_cache() -> None:
    global _status_cache
    with _cache_lock:
        _cache.clear()
        _status_cache = None


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(status: str, **extra: Any) -> dict[str, Any]:
    return {"provider": "Google Safe Browsing", "status": status, "checked_at": _timestamp(), **extra}


def _request_body(url: str) -> dict[str, Any]:
    return {
        "client": {"clientId": "digital-trust-intelligence", "clientVersion": "0.4"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def _error_status(response: httpx.Response) -> tuple[str, str]:
    message = "provider_http_error"
    try:
        payload = response.json()
        message = str(payload.get("error", {}).get("message") or message).lower()
    except (ValueError, TypeError):
        pass
    if "disabled" in message or "not been used" in message or "enable" in message:
        return "api_not_enabled", message
    if "quota" in message or ("limit" in message and response.status_code in (403, 429)):
        return "quota_exceeded", message
    if response.status_code == 429:
        return "rate_limited", message
    if response.status_code in (401, 403) or "credential" in message or "api key" in message:
        return "invalid_credentials", message
    if response.status_code >= 500:
        return "provider_error", message
    return "error", message


def lookup(url: str) -> dict[str, Any]:
    """Query Safe Browsing v4 and return a normalized provider result."""
    key = settings.google_safe_browsing_api_key.strip()
    if not key:
        return _result("not_configured", verdict="unknown", reason="API key not configured")

    with _cache_lock:
        cached = _cache.get(url)
        if cached and time.monotonic() - cached[0] < settings.google_safe_browsing_status_cache_seconds:
            result = dict(cached[1]); result["cache"] = "hit"; return result
    endpoint = settings.google_safe_browsing_api_url
    attempts = max(1, settings.google_safe_browsing_max_retries + 1)
    for attempt in range(attempts):
        try:
            response = httpx.post(
                endpoint,
                params={"key": key},
                json=_request_body(url),
                timeout=settings.google_safe_browsing_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.TimeoutException:
            if attempt + 1 < attempts:
                time.sleep(settings.google_safe_browsing_retry_backoff_seconds * (attempt + 1))
                continue
            return _result("timeout", verdict="unknown", reason="provider request timed out")
        except httpx.RequestError as exc:
            if attempt + 1 < attempts:
                time.sleep(settings.google_safe_browsing_retry_backoff_seconds * (attempt + 1))
                continue
            return _result("unavailable", verdict="unknown", reason=type(exc).__name__)

        if response.status_code >= 500 or response.status_code in (429, 408):
            if attempt + 1 < attempts:
                time.sleep(settings.google_safe_browsing_retry_backoff_seconds * (attempt + 1))
                continue
        if response.status_code < 200 or response.status_code >= 300:
            status, reason = _error_status(response)
            return _result(status, verdict="unknown", reason=reason, http_status=response.status_code)

        try:
            payload = response.json()
        except (ValueError, TypeError):
            return _result("invalid_response", verdict="unknown", reason="malformed JSON")
        if not isinstance(payload, dict) or ("matches" in payload and not isinstance(payload["matches"], list)):
            return _result("invalid_response", verdict="unknown", reason="unexpected response format")

        matches = payload.get("matches", [])
        normalized = []
        for match in matches:
            if not isinstance(match, dict) or not match.get("threatType"):
                return _result("invalid_response", verdict="unknown", reason="invalid threat match format")
            normalized.append({
                "threat_type": match.get("threatType"),
                "platform_type": match.get("platformType"),
                "threat_entry_type": match.get("threatEntryType"),
                "threat_entry": match.get("threatEntry"),
                "cache_duration": match.get("cacheDuration"),
                "metadata": match.get("threat"),
            })
        result = _result("queried", verdict="malicious" if normalized else "no_match",
                         matches=normalized, threat_categories=sorted({x["threat_type"] for x in normalized}),
                         requested_threat_types=THREAT_TYPES)
        with _cache_lock:
            _cache[url] = (time.monotonic(), result)
        return result
    return _result("unavailable", verdict="unknown", reason="provider retries exhausted")


def configuration_status() -> dict[str, Any]:
    """Return safe configuration diagnostics without returning credentials."""
    configured = bool(settings.google_safe_browsing_api_key.strip())
    return {
        "provider": "Google Safe Browsing",
        "api_version": "v4",
        "endpoint": settings.google_safe_browsing_api_url,
        "api_key_configured": configured,
        "project_id_configured": bool(settings.google_cloud_project_id.strip()),
        "provider_initialized": True,
        "connection_status": "CONFIGURED_NOT_TESTED" if configured else "NOT_CONFIGURED",
        "threat_types": THREAT_TYPES,
        "last_checked": None,
    }


def verify_connection(force: bool = False) -> dict[str, Any]:
    """Perform a controlled, cached verification with Google's documented test URL."""
    global _status_cache
    now = time.monotonic()
    if not force and _status_cache and now - _status_cache[0] < settings.google_safe_browsing_status_cache_seconds:
        return dict(_status_cache[1])
    base = configuration_status()
    if not base["api_key_configured"]:
        result = {**base, "connection_status": "NOT_CONFIGURED", "last_checked": _timestamp()}
    else:
        result_lookup = lookup(TEST_URL)
        state_map = {
            "queried": "CONNECTED", "invalid_credentials": "INVALID_CREDENTIALS",
            "api_not_enabled": "API_NOT_ENABLED", "rate_limited": "RATE_LIMITED",
            "quota_exceeded": "QUOTA_EXCEEDED", "timeout": "TEMPORARY_FAILURE",
            "provider_error": "TEMPORARY_FAILURE", "unavailable": "TEMPORARY_FAILURE",
        }
        result = {**base, "connection_status": state_map.get(result_lookup["status"], "UNKNOWN"),
                  "last_checked": result_lookup.get("checked_at"), "verification": result_lookup}
    _status_cache = (time.monotonic(), result)
    return result
