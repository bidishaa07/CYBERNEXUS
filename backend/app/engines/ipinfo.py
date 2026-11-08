"""Safe, plan-aware IPinfo integration for domain infrastructure intelligence."""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from backend.app.core.config import settings
from backend.app.engines.network_intelligence import lookup_ripe, enrich_record

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()

def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _is_global(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

def resolve_domain_ips(domain: str) -> tuple[list[str], list[str]]:
    public: set[str] = set(); restricted: set[str] = set()
    try:
        for record in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM):
            address = record[4][0]
            if _is_global(address):
                public.add(address)
            else:
                restricted.add(address)
    except (OSError, socket.gaierror):
        return [], []
    return sorted(public, key=lambda x: (":" in x, x)), sorted(restricted)

def _parse_asn(data: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    asn_number = organization = as_domain = None
    raw_org = data.get("org")
    if isinstance(raw_org, str):
        match = re.match(r"\s*(AS\d+)\s*(.*)", raw_org, re.I)
        if match:
            asn_number, organization = match.group(1).upper(), match.group(2).strip() or None
        elif raw_org.strip():
            organization = raw_org.strip()
    raw_asn = data.get("asn")
    if isinstance(raw_asn, dict):
        asn_number = asn_number or raw_asn.get("asn")
        organization = organization or raw_asn.get("name") or raw_asn.get("organization")
        as_domain = raw_asn.get("domain")
    elif raw_asn is not None:
        value = str(raw_asn)
        asn_number = asn_number or (value if value.upper().startswith("AS") else f"AS{value}")
        organization = organization or data.get("as_name") or data.get("asn_name")
    as_domain = as_domain or data.get("as_domain") or data.get("as-domain")
    return asn_number, organization, as_domain

def _normalise(ip: str, data: dict[str, Any]) -> dict[str, Any]:
    asn_number, organization, as_domain = _parse_asn(data)
    optional = {name: data.get(name) for name in ("hosting", "privacy", "anycast", "bogon")}
    extended = {"network_range": data.get("network") or data.get("prefix") or (data.get("asn") or {}).get("route") if isinstance(data.get("asn"), dict) else None,
                "network_type": data.get("network_type") or data.get("type"), "isp": data.get("isp") or data.get("as_name"),
                "hosting_provider": data.get("hosting_provider") or data.get("host_provider"), "cloud_provider": data.get("cloud_provider"),
                "data_center": data.get("data_center"), "classification": data.get("hosting_type") or data.get("network_classification")}
    return {"source": "IPinfo", "ip": ip, "status": "queried", "asn_number": asn_number,
            "asn_organization": organization, "asn_domain": as_domain,
            "country": data.get("country_code") or data.get("country"), "country_name": data.get("country") or data.get("country_name"),
            "region": data.get("region"), "city": data.get("city"), "hostname": data.get("hostname"),
            "loc": data.get("loc"), **optional, **extended,
            "unavailable_fields": [key for key, value in {**optional, **extended}.items() if value is None],
            "checked_at": _now()}

def lookup_ip(ip: str, token: str | None = None) -> dict[str, Any]:
    token = settings.ipinfo_token if token is None else token
    if not token:
        return {"source": "IPinfo", "ip": ip, "status": "not_configured", "message": "IPINFO_TOKEN is not configured."}
    if not _is_global(ip):
        return {"source": "IPinfo", "ip": ip, "status": "skipped_restricted", "message": "Restricted IP was not queried."}
    with _cache_lock:
        cached = _cache.get(ip)
        if cached and time.monotonic() - cached[0] < settings.ipinfo_cache_ttl_seconds:
            result = dict(cached[1]); result["cache"] = "hit"; return result
    try:
        base = settings.ipinfo_base_url.rstrip("/")
        endpoint = f"{base}/{ip}" if base.lower().endswith("/lite") else f"{base}/{ip}/json"
        response = httpx.get(endpoint,
                             headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                             timeout=settings.ipinfo_timeout_seconds, follow_redirects=False)
    except httpx.TimeoutException:
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "error": "timeout"}
    except (httpx.HTTPError, OSError):
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "error": "network_error"}
    if response.status_code in (401, 403):
        return {"source": "IPinfo", "ip": ip, "status": "invalid_credentials", "http_status": response.status_code}
    if response.status_code == 429:
        return {"source": "IPinfo", "ip": ip, "status": "rate_limited", "http_status": 429}
    if response.status_code >= 500:
        return {"source": "IPinfo", "ip": ip, "status": "provider_error", "http_status": response.status_code}
    if response.status_code != 200:
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "http_status": response.status_code}
    if response.headers.get("content-type") and "json" not in response.headers["content-type"].lower():
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "error": "unexpected_content_type"}
    try:
        data = response.json()
    except (ValueError, TypeError):
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "error": "malformed_json"}
    if not isinstance(data, dict):
        return {"source": "IPinfo", "ip": ip, "status": "unavailable", "error": "invalid_response"}
    result = _normalise(ip, data)
    with _cache_lock:
        _cache[ip] = (time.monotonic(), result)
    return result


def lookup_freeipapi(ip: str) -> dict[str, Any]:
    """No-key fallback for geolocation and basic ASN fields.

    FreeIPAPI does not provide IPinfo's full reputation/hosting schema; those
    fields remain explicitly unavailable.
    """
    try:
        response = httpx.get(f"{settings.freeipapi_base_url.rstrip('/')}/{ip}", timeout=settings.ipinfo_timeout_seconds, follow_redirects=True)
    except httpx.TimeoutException:
        return {"source": "FreeIPAPI", "ip": ip, "status": "unavailable", "error": "timeout"}
    except (httpx.HTTPError, OSError):
        return {"source": "FreeIPAPI", "ip": ip, "status": "unavailable", "error": "network_error"}
    if response.status_code != 200:
        return {"source": "FreeIPAPI", "ip": ip, "status": "unavailable", "http_status": response.status_code}
    try:
        data = response.json()
    except (ValueError, TypeError):
        return {"source": "FreeIPAPI", "ip": ip, "status": "unavailable", "error": "malformed_json"}
    if not isinstance(data, dict):
        return {"source": "FreeIPAPI", "ip": ip, "status": "unavailable", "error": "invalid_response"}
    asn = data.get("asn")
    return {"source": "FreeIPAPI", "ip": ip, "status": "queried", "asn_number": f"AS{asn}" if asn else None,
            "asn_organization": data.get("asnOrganization"), "asn_domain": None,
            "country": data.get("countryCode"), "country_name": data.get("countryName"),
            "region": data.get("regionName"), "city": data.get("cityName"),
            "hostname": None, "hosting": None, "hosting_provider": None, "network_range": None, "network_type": None, "isp": data.get("isp"), "cloud_provider": None, "data_center": None, "classification": None, "privacy": {"is_proxy": data.get("isProxy")} if "isProxy" in data else None,
            "anycast": None, "bogon": None,
            "unavailable_fields": ["asn_domain", "hostname", "hosting", "anycast", "bogon"], "checked_at": _now()}

def collect_ip_intelligence(domain: str) -> dict[str, Any]:
    public_ips, restricted_ips = resolve_domain_ips(domain)
    result: dict[str, Any] = {"domain": domain, "ips": public_ips,
        "resolved_ips": [{"ip": ip, "version": "IPv6" if ":" in ip else "IPv4"} for ip in public_ips],
        "restricted_ips": restricted_ips, "providers": [],
        "provider": {"name": "IPinfo" if settings.ipinfo_token else "FreeIPAPI", "configured": bool(settings.ipinfo_token) or settings.ip_intelligence_provider.lower() == "freeipapi",
                      "cache_ttl_seconds": settings.ipinfo_cache_ttl_seconds},
        "status": "available" if public_ips else "unavailable"}
    use_freeipapi = not settings.ipinfo_token and settings.ip_intelligence_provider.lower() == "freeipapi"
    if not settings.ipinfo_token and not use_freeipapi:
        result.update(status="not_configured", provider_status="missing_credentials"); return result
    if not public_ips:
        result["provider_status"] = "dns_unavailable"; return result
    for ip in public_ips[:settings.ipinfo_max_ips_per_scan]:
        item = lookup_ip(ip) if settings.ipinfo_token else lookup_freeipapi(ip)
        # RIPE Stat is used only to fill authoritative routing gaps; it is not
        # treated as a hosting or reputation verdict.
        fallback = lookup_ripe(ip) if (not item.get("asn_number") or not item.get("network_range")) else {"source":"RIPE Stat","ip":ip,"status":"not_needed"}
        result["providers"].append(enrich_record(item, fallback))
        if item.get("status") == "rate_limited":
            result["provider_status"] = "rate_limited"; break
    statuses = {item.get("status") for item in result["providers"]}
    result["status"] = "partial" if "queried" in statuses and len(statuses) > 1 else ("available" if "queried" in statuses else "unavailable")
    result.setdefault("provider_status", "available" if "queried" in statuses else next(iter(statuses), "unavailable"))
    return result
