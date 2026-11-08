import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

def normalize_url(raw: str):
    value = raw.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only valid HTTP(S) URLs are supported")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # A valid-looking but currently unresolvable host can still be analyzed
        # for URL/phishing indicators. Network engines will report DNS/TLS as
        # unavailable instead of turning the whole scan into a 500 error.
        addresses = []
    for addr in addresses:
        ip = ipaddress.ip_address(addr[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError("Private or restricted network destinations are blocked")
    netloc = host + ((f":{parsed.port}") if parsed.port else "")
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, "")), host
