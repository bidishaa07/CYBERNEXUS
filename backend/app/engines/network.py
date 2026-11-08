import socket, ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from backend.app.engines.url_utils import normalize_url
from backend.app.engines.safe_http import fetch as safe_fetch, UnsafeDestination, resolve_public_ips
from backend.app.core.config import settings
from backend.app.engines.advanced_security import analyze_response
from backend.app.engines.tls_http_assessment import analyze_hsts, analyze_redirect_chain, analyze_disclosure, check_hsts_preload
from backend.app.services.security_authorization import AuthorizationStopped

SECURITY_HEADERS={"content-security-policy":"Content Security Policy","strict-transport-security":"HSTS","x-content-type-options":"X-Content-Type-Options","x-frame-options":"Clickjacking protection","referrer-policy":"Referrer Policy"}
def inspect(url: str, domain: str, authorization_guard=None):
    result={"http":{"status":"unavailable","headers":{},"redirects":[],"observations":[],"final_url":url,"complete":False},"tls":{"status":"unavailable"},"dns":{"status":"available"},"evidence":[],"findings":[],"unavailable":[]}; current=url; seen={url}
    response_body=b""
    try:
        for sequence in range(settings.max_redirect_hops):
            if authorization_guard:
                authorization_guard()
            response=safe_fetch(current, timeout=5.0, max_bytes=settings.max_page_size_bytes)
            if authorization_guard:
                authorization_guard()
            response_body=response.body
            headers={k.lower():v for k,v in response.headers.items() if k.lower() in set(SECURITY_HEADERS)|{"set-cookie","server","location","access-control-allow-origin","access-control-allow-credentials","access-control-allow-methods","access-control-allow-headers","access-control-expose-headers","access-control-max-age","cache-control","pragma","expires","permissions-policy","cross-origin-opener-policy","cross-origin-embedder-policy","cross-origin-resource-policy"}}
            result["http"].update({"status":response.status_code,"headers":headers,"final_url":current})
            result["http"]["observations"].append({"url":current,"status":response.status_code,"headers":headers,"location":response.headers.get("location")})
            if response.status_code not in {301,302,303,307,308}:
                result["http"]["complete"]=True; break
            location=response.headers.get("location")
            if not location:
                result["unavailable"].append("Redirect response has no Location header"); break
            destination=urljoin(current,location)
            try: normalized,next_domain=normalize_url(destination)
            except ValueError as exc:
                result["findings"].append({"issue":"Redirect destination blocked","evidence":destination,"severity":"high","impact":"Redirect points to a restricted or invalid destination","remediation":"Do not follow the redirect","limitation":str(exc)}); break
            if normalized in seen:
                result["unavailable"].append("Redirect loop detected"); break
            addresses=resolve_public_ips(next_domain)
            hop={"sequence":sequence+1,"source_url":current,"destination_url":normalized,"source_domain":(urlparse(current).hostname or ""),"destination_domain":next_domain,"status_code":response.status_code,"redirect_type":f"HTTP {response.status_code}","https":normalized.startswith("https://"),"https_downgrade":current.startswith("https://") and normalized.startswith("http://"),"destination_ips":addresses,"analysis_status":"complete","checked_at":datetime.now(timezone.utc).isoformat()}
            result["http"]["redirects"].append(hop); seen.add(normalized); current=normalized
        else:
            result["unavailable"].append("Maximum redirect depth exceeded")
        if authorization_guard:
            authorization_guard()
        for header,label in SECURITY_HEADERS.items():
            if header not in result["http"]["headers"]: result["findings"].append({"issue":f"Missing {label}","evidence":header,"severity":"medium","impact":"Browser protections may be weaker","remediation":f"Configure {label} for the site","limitation":"Header absence alone does not prove exploitation"})
        cookie=result["http"]["headers"].get("set-cookie","")
        cookie_text="; ".join(cookie) if isinstance(cookie,list) else cookie
        if cookie_text and ("secure" not in cookie_text.lower() or "httponly" not in cookie_text.lower()): result["findings"].append({"issue":"Cookie missing Secure or HttpOnly attribute","evidence":cookie_text[:300],"severity":"medium","impact":"Session cookies may be more exposed","remediation":"Set Secure and HttpOnly where appropriate","limitation":"Only response cookies from one request were inspected"})
        advanced=analyze_response(result["http"]["headers"], response_body, current)
        hsts=analyze_hsts(result["http"]["headers"], current, result["http"]["observations"])
        preload_status=None
        if hsts["details"].get("preload_eligible"):
            preload_status=check_hsts_preload(domain)
            hsts=analyze_hsts(result["http"]["headers"], current, result["http"]["observations"], preload_status)
        redirects=analyze_redirect_chain(url, result["http"], settings.max_redirect_hops)
        disclosure=analyze_disclosure(result["http"]["headers"])
        advanced.update({"hsts":hsts, "redirects":redirects["report"], "disclosure":disclosure})
        result["advanced_security"]=advanced
        result["findings"].extend(advanced["findings"])
        result["findings"].append(hsts["finding"]); result["findings"].extend(redirects["findings"]); result["findings"].append(disclosure["finding"])
    except (UnsafeDestination, ValueError) as exc: result["unavailable"].append(f"HTTP check blocked or unavailable: {str(exc)}")
    except (socket.timeout, TimeoutError) as exc: result["unavailable"].append(f"HTTP check timeout: {type(exc).__name__}")
    except AuthorizationStopped:
        raise
    except Exception as exc:
        result["unavailable"].append(f"HTTP check unavailable: {type(exc).__name__}")
    try:
        if authorization_guard:
            authorization_guard()
        ctx=ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=5) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as tls: result["tls"]={"status":"valid","protocol":tls.version(),"cipher":tls.cipher(),"hostname_match":True}
    except Exception as exc:
        result["tls"]={"status":"failed","hostname_match":False}; result["findings"].append({"issue":"TLS validation failed or unavailable","evidence":type(exc).__name__,"severity":"high","impact":"Encrypted transport trust could not be established","remediation":"Use a valid certificate and modern TLS configuration","limitation":"A network failure may also cause this result"})
    result["evidence"]=result["findings"]; return result
