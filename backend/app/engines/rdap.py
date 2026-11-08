"""Safe RDAP discovery and retrieval.

Redirects are handled manually so every hop is HTTPS, resolved before use,
and either the trusted RDAP bootstrap host or an authoritative bootstrap host.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urljoin, urlparse

import httpx

from backend.app.core.config import settings

logger = logging.getLogger("digital_trust.rdap")
REDIRECT_CODES = {301, 302, 303, 307, 308}
BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata.azure.com", "instance-data.ec2.internal"}
BLOCKED_IPS = {"169.254.169.254", "100.100.100.200"}

class RDAPError(Exception):
    def __init__(self, status: str, reason: str, http_status: int | None = None):
        super().__init__(reason); self.status=status; self.reason=reason; self.http_status=http_status

def _host_ips(host: str):
    try:
        answers=socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RDAPError("unavailable", "DNS resolution failed") from exc
    ips=sorted({item[4][0] for item in answers})
    if not ips: raise RDAPError("unavailable", "DNS returned no addresses")
    for raw in ips:
        try: ip=ipaddress.ip_address(raw)
        except ValueError: raise RDAPError("failed", "Invalid DNS address")
        if raw in BLOCKED_IPS or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise RDAPError("blocked", "RDAP destination resolves to a restricted address")
    return ips

def _validate_https_url(url: str, allowed_hosts: set[str]):
    parsed=urlparse(url); host=(parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise RDAPError("blocked", "RDAP requests and redirects must use HTTPS without credentials")
    if host in BLOCKED_HOSTS or host not in allowed_hosts:
        raise RDAPError("blocked", "RDAP redirect host is not trusted")
    _host_ips(host)  # Resolve at every hop to reduce DNS-rebinding exposure.
    return parsed

@lru_cache(maxsize=1)
def _bootstrap_hosts():
    """Return RDAP hosts from IANA DNS bootstrap data.

    rdap.org is allowed as the discovery entry point; redirects are only
    allowed to hosts advertised by this trusted IANA document.
    """
    hosts={"rdap.org"}
    try:
        response=httpx.get(settings.rdap_bootstrap_url, timeout=settings.rdap_timeout_seconds, follow_redirects=False)
        if response.status_code != 200: return hosts
        if "json" not in response.headers.get("content-type", "").lower(): return hosts
        data=response.json()
        for service in data.get("services", []):
            if len(service) >= 2:
                hosts.update((urlparse(x).hostname or "").lower().rstrip(".") for x in service[1] if urlparse(x).scheme == "https")
    except Exception as exc:
        logger.warning("RDAP bootstrap unavailable: %s", type(exc).__name__)
    return {x for x in hosts if x}

def _parse(domain: str, data: dict, final_url: str):
    events={}
    for event in data.get("events", []):
        action=event.get("eventAction"); date=event.get("eventDate")
        if action and date: events[action]=date
    registrar=None; registrant_organization=None
    for entity in data.get("entities", []):
        v=entity.get("vcardArray", [None, []])
        if "registrant" in entity.get("roles", []):
            registrant_organization=next((row[3] for row in v[1] if row and row[0] == "org" and len(row)>3), None)
        if "registrar" in entity.get("roles", []):
            registrar=next((row[3] for row in v[1] if row and row[0] == "fn" and len(row)>3), None)
            break
    return {"status":"available","source":"RDAP","domain":domain,"final_url":final_url,"handle":data.get("handle"),"ldh_name":data.get("ldhName"),"events":events,"registrar":registrar,"registrant_organization":registrant_organization,"nameservers":[x.get("ldhName") for x in data.get("nameservers",[]) if x.get("ldhName")],"status_codes":data.get("status",[]),"privacy_redacted":not bool(data.get("entities")),"checked_at":datetime.now(timezone.utc).isoformat()}

def fetch_rdap(domain: str, *, bootstrap_hosts: set[str] | None = None):
    original=domain.lower().rstrip("."); allowed=bootstrap_hosts or _bootstrap_hosts(); current=f"https://rdap.org/domain/{original}"; redirects=[]
    try:
        for hop in range(settings.rdap_max_redirects + 1):
            _validate_https_url(current, allowed)
            with httpx.Client(follow_redirects=False, timeout=httpx.Timeout(settings.rdap_timeout_seconds, connect=settings.rdap_timeout_seconds)) as client:
                response=client.get(current, headers={"Accept":"application/rdap+json, application/json"})
            if response.status_code in REDIRECT_CODES:
                if hop >= settings.rdap_max_redirects: raise RDAPError("failed", "Maximum RDAP redirects exceeded")
                location=response.headers.get("location")
                if not location: raise RDAPError("failed", "RDAP redirect has no Location header")
                next_url=urljoin(current, location); _validate_https_url(next_url, allowed)
                redirects.append({"hop":hop+1,"from":current,"to":next_url,"status_code":response.status_code}); current=next_url; continue
            if response.status_code == 429: raise RDAPError("rate_limited", "RDAP provider rate limit", 429)
            if 500 <= response.status_code <= 599: raise RDAPError("unavailable", "RDAP provider server error", response.status_code)
            if response.status_code < 200 or response.status_code >= 300: raise RDAPError("unavailable", "RDAP provider returned an error", response.status_code)
            content_type=response.headers.get("content-type", "").lower()
            if "json" not in content_type: raise RDAPError("failed", "RDAP response was not JSON")
            if not response.content: raise RDAPError("failed", "RDAP response was empty")
            try: data=response.json()
            except (json.JSONDecodeError, ValueError) as exc: raise RDAPError("failed", "RDAP response contained malformed JSON") from exc
            result=_parse(original, data, current); result["redirects"]=redirects; return result
        raise RDAPError("failed", "RDAP redirect loop")
    except RDAPError as exc:
        logger.info("RDAP %s: %s", original, exc.reason)
        return {"status":exc.status,"source":"RDAP","domain":original,"reason":exc.reason,"http_status":exc.http_status,"redirects":redirects,"checked_at":datetime.now(timezone.utc).isoformat()}
    except (httpx.TimeoutException, socket.timeout):
        logger.info("RDAP %s: timeout", original)
        return {"status":"unavailable","source":"RDAP","domain":original,"reason":"timeout","redirects":redirects}
    except httpx.RequestError as exc:
        logger.info("RDAP %s: network error %s", original, type(exc).__name__)
        return {"status":"unavailable","source":"RDAP","domain":original,"reason":"network_error","redirects":redirects}
    except Exception as exc:
        logger.exception("RDAP unexpected failure for %s", original)
        return {"status":"failed","source":"RDAP","domain":original,"reason":type(exc).__name__,"redirects":redirects}
