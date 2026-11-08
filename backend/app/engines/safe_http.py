"""Small, fail-closed HTTP fetcher for untrusted redirect destinations.

The socket is opened against an address resolved and validated by this module;
the hostname is retained for TLS SNI, certificate verification, and Host.
"""
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from backend.app.core.config import settings
try:
    import certifi
except ImportError:  # pragma: no cover
    certifi = None

METADATA_IPS = {"169.254.169.254", "100.100.100.200"}

class UnsafeDestination(ValueError):
    pass

@dataclass
class SafeResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes

def post_binary(url: str, body: bytes, content_type: str, timeout: float = 5.0, max_bytes: int | None = None) -> SafeResponse:
    """Pinned, one-shot POST for binary protocol endpoints such as OCSP."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeDestination("only credential-free HTTP(S) destinations are allowed")
    ips = resolve_public_ips(parsed.hostname)
    ip = ips[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=certifi.where() if certifi else None)
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = parsed.hostname
        if parsed.port and parsed.port not in {80, 443}:
            host_header += f":{parsed.port}"
        request = (f"POST {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: DigitalTrustIntelligence/1.0\r\nContent-Type: {content_type}\r\nAccept: application/ocsp-response, application/pkix-crl\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii", "strict") + body
        sock.sendall(request)
        response = http.client.HTTPResponse(sock, method="POST")
        response.begin()
        limit = max_bytes or settings.max_page_size_bytes
        response_body = response.read(limit + 1)
        if len(response_body) > limit:
            raise ValueError("response size limit exceeded")
        return SafeResponse(response.status, {key.lower(): value for key, value in response.getheaders()}, response_body)
    finally:
        sock.close()

def _public_ip(value: str) -> ipaddress._BaseAddress:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (str(address) in METADATA_IPS or not address.is_global or address.is_loopback or address.is_private or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast):
        raise UnsafeDestination("destination resolves to a restricted address")
    return address

def resolve_public_ips(hostname: str) -> list[str]:
    answers = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    values = sorted({item[4][0] for item in answers})
    if not values:
        raise UnsafeDestination("destination did not resolve")
    validated = [_public_ip(value) for value in values]
    if len(validated) != len(values):
        raise UnsafeDestination("mixed public and restricted DNS answers are blocked")
    return [str(value) for value in validated]

def fetch(url: str, timeout: float = 5.0, max_bytes: int | None = None) -> SafeResponse:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeDestination("only credential-free HTTP(S) destinations are allowed")
    ips = resolve_public_ips(parsed.hostname)
    # A fresh connection is deliberately created for each hop; no pool can
    # reuse an address validated for a different hostname.
    ip = ips[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=certifi.where() if certifi else None)
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host_header = parsed.hostname
        if parsed.port and parsed.port not in {80, 443}:
            host_header += f":{parsed.port}"
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: DigitalTrustIntelligence/1.0\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.1\r\nConnection: close\r\n\r\n").encode("ascii", "strict")
        sock.sendall(request)
        response = http.client.HTTPResponse(sock, method="GET")
        response.begin()
        limit = max_bytes or settings.max_page_size_bytes
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError("response size limit exceeded")
        return SafeResponse(response.status, {key.lower(): value for key, value in response.getheaders()}, body)
    finally:
        sock.close()
