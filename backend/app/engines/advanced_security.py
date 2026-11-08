"""Non-intrusive browser and HTTP security policy analysis.

The checks operate on one already-fetched response. They never send an
arbitrary Origin request or fetch subresources, so the result is evidence from
the observed response rather than an intrusive vulnerability probe.
"""
import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


def _finding(check, title, *, status="UNKNOWN", severity="INFO", confidence="HIGH",
             observed=None, expected=None, impact="", remediation="", evidence=None,
             limitation=""):
    return {"category": "HTTP", "check_identifier": check, "title": title,
            "status": status, "severity": severity, "confidence": confidence,
            "observed_value": observed, "expected_value": expected,
            "impact": impact, "remediation": remediation, "evidence": evidence or {},
            "limitation": limitation}


def _header(headers, name):
    value = (headers or {}).get(name.lower())
    return value


def _cookie_headers(headers):
    value = _header(headers, "set-cookie")
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return re.split(r",\s*(?=[^;,=\s]+\s*=)", value)


def analyze_cookies(headers, page_url):
    cookies = _cookie_headers(headers)
    findings = []
    if not cookies:
        return [_finding("cookie_policy", "Cookie policy", status="NOT_APPLICABLE",
                         observed="No Set-Cookie header observed",
                         expected="Context-dependent cookie attributes", evidence={},
                         limitation="Only response cookies from the observed request were inspected.")]
    for index, raw in enumerate(cookies):
        pieces = [x.strip() for x in raw.split(";")]
        if not pieces or "=" not in pieces[0]:
            findings.append(_finding(f"cookie_{index}_syntax", "Malformed Set-Cookie header",
                                     status="FAIL", severity="MEDIUM", observed=raw[:500],
                                     expected="name=value cookie syntax",
                                     remediation="Return syntactically valid Set-Cookie headers."))
            continue
        name, _ = pieces[0].split("=", 1)
        attrs = {}
        for piece in pieces[1:]:
            if "=" in piece:
                key, val = piece.split("=", 1)
                attrs[key.strip().lower()] = val.strip()
            else:
                attrs[piece.strip().lower()] = True
        lname = name.strip().lower()
        sensitive = bool(re.search(r"(session|sess|auth|token|csrf|jwt|sid|login|password|payment)", lname))
        same = str(attrs.get("samesite", "missing")).lower()
        if same == "none" and "secure" not in attrs:
            findings.append(_finding(f"cookie_{index}_samesite_secure",
                                     f"{name}: SameSite=None without Secure", status="FAIL",
                                     severity="HIGH", observed=raw[:500],
                                     expected="SameSite=None cookies must also set Secure",
                                     impact="The cookie may be sent cross-site without transport protection.",
                                     remediation="Add Secure or use a stricter SameSite value when cross-site use is not required."))
        elif same not in {"strict", "lax", "none", "missing"}:
            findings.append(_finding(f"cookie_{index}_samesite", f"{name}: invalid SameSite value",
                                     status="FAIL", severity="MEDIUM", observed=same,
                                     expected="Strict, Lax or None",
                                     remediation="Use a standards-compliant SameSite value."))
        else:
            findings.append(_finding(f"cookie_{index}_samesite", f"{name}: SameSite policy",
                                     status="PASS" if same != "missing" else "WARNING",
                                     severity="INFO" if same != "missing" else "LOW",
                                     observed=same,
                                     expected="Explicit SameSite policy where appropriate",
                                     evidence={"cookie_name": name, "samesite": same},
                                     limitation="The required cross-site behavior is application-context dependent."))
        if page_url.lower().startswith("https://") and "secure" not in attrs:
            findings.append(_finding(f"cookie_{index}_secure", f"{name}: Secure attribute",
                                     status="WARNING" if sensitive else "PASS",
                                     severity="MEDIUM" if sensitive else "INFO",
                                     observed="missing", expected="Secure for sensitive HTTPS cookies",
                                     impact="A sensitive cookie may be sent over a non-TLS request.",
                                     remediation="Set Secure on sensitive cookies served over HTTPS."))
        else:
            findings.append(_finding(f"cookie_{index}_secure", f"{name}: Secure attribute",
                                     status="PASS", observed="present" if "secure" in attrs else "not required by observed context",
                                     expected="Context-dependent"))
        findings.append(_finding(
            f"cookie_{index}_httponly", f"{name}: HttpOnly attribute",
            status="PASS" if "httponly" in attrs or not sensitive else "WARNING",
            severity="MEDIUM" if sensitive and "httponly" not in attrs else "INFO",
            observed="present" if "httponly" in attrs else "missing",
            expected="HttpOnly for non-script-readable sensitive cookies",
            impact="A script-accessible session cookie has greater exposure to script injection.",
            remediation="Set HttpOnly unless client-side JavaScript must read the cookie."))
        path = attrs.get("path", "default")
        domain = attrs.get("domain")
        findings.append(_finding(
            f"cookie_{index}_scope", f"{name}: scope",
            status="WARNING" if sensitive and (path == "/" or domain) else "PASS",
            severity="LOW" if sensitive and (path == "/" or domain) else "INFO",
            observed={"path": path, "domain": domain or "host-only"},
            expected="Narrowest required Path and host-only scope",
            impact="Broad path or domain scope increases the set of requests carrying a sensitive cookie.",
            remediation="Restrict Path and omit Domain unless sharing across subdomains is required."))
        expiry = {key: attrs[key] for key in ("expires", "max-age") if key in attrs}
        findings.append(_finding(
            f"cookie_{index}_lifetime", f"{name}: lifetime", status="PASS",
            observed=expiry or "session cookie",
            expected="A lifetime appropriate to the session purpose",
            evidence={"cookie_name": name, "lifetime": expiry},
            limitation="Whether persistence is appropriate depends on application requirements."))
    return findings


def analyze_cors(headers):
    origin = _header(headers, "access-control-allow-origin")
    credentials = _header(headers, "access-control-allow-credentials")
    observed = {
        "allow_origin": origin,
        "allow_credentials": credentials,
        "allow_methods": _header(headers, "access-control-allow-methods"),
        "allow_headers": _header(headers, "access-control-allow-headers"),
        "expose_headers": _header(headers, "access-control-expose-headers"),
        "max_age": _header(headers, "access-control-max-age"),
    }
    if origin is None:
        return [_finding("cors_policy", "CORS policy", status="NOT_APPLICABLE",
                         observed="No CORS response header observed",
                         expected="A deliberate CORS policy where cross-origin access is required",
                         evidence=observed,
                         limitation="No Origin request was sent; reflected-origin behavior was not probed.")]
    if str(origin).strip() == "*" and str(credentials or "").lower() == "true":
        return [_finding("cors_policy", "Credentialed wildcard CORS", status="FAIL",
                         severity="HIGH", observed=observed,
                         expected="Specific trusted origins for credentialed access",
                         impact="Broad credential policy can expose cross-origin data when changed or reflected.",
                         remediation="Use an explicit allowlist and enable credentials only for trusted origins.",
                         evidence=observed,
                         limitation="Only response headers were inspected; no unauthorized cross-origin request was made.")]
    if str(origin).strip() == "*":
        return [_finding("cors_policy", "Wildcard CORS origin", status="WARNING",
                         severity="LOW", observed=observed,
                         expected="Wildcard only for intentionally public non-credentialed resources",
                         impact="Any origin may read resources that are eligible for CORS.",
                         remediation="Use a specific origin allowlist for sensitive resources.",
                         evidence=observed,
                         limitation="Wildcard CORS is not automatically a vulnerability; resource sensitivity was not determined.")]
    return [_finding("cors_policy", "CORS policy", status="PASS",
                     observed=observed, expected="Specific, intentional origin policy",
                     evidence=observed,
                     limitation="Reflected-origin behavior was not verifiable without sending an Origin request.")]


class _ResourceParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        tag = tag.lower()
        if tag in {"script", "iframe", "img", "audio", "video", "source", "track", "embed", "object"} and data.get("src"):
            self.resources.append((tag, data["src"]))
        if tag == "link" and data.get("href") and str(data.get("rel", "")).lower() in {"stylesheet", "preload", "modulepreload"}:
            self.resources.append(("stylesheet", data["href"]))


def analyze_mixed_content(body, page_url):
    if not page_url.lower().startswith("https://"):
        return []
    parser = _ResourceParser()
    try:
        parser.feed((body or b"")[:1000000].decode("utf-8", "replace"))
    except Exception:
        return [_finding("mixed_content_parse", "Mixed-content inspection",
                         status="UNKNOWN", confidence="LOW",
                         limitation="HTML could not be parsed safely.")]
    findings = []
    active = {"script", "stylesheet", "iframe", "object", "embed"}
    for tag, raw_url in parser.resources:
        absolute = urljoin(page_url, raw_url)
        if urlparse(absolute).scheme.lower() != "http":
            continue
        kind = "active" if tag in active else "passive"
        digest = hashlib.sha256(absolute.encode()).hexdigest()[:16]
        findings.append(_finding(
            f"mixed_content_{digest}", f"HTTP {kind} mixed content", status="FAIL",
            severity="HIGH" if kind == "active" else "MEDIUM", observed=absolute,
            expected="HTTPS subresource URL",
            impact=f"An HTTPS page references {kind} content over HTTP.",
            remediation="Serve the resource over HTTPS and update the page reference.",
            evidence={"resource_url": absolute, "element": tag, "type": kind},
            limitation="The resource was identified from HTML only and was not fetched."))
    return findings or [_finding("mixed_content", "Mixed-content inspection", status="PASS",
                                 observed="No HTTP subresources observed",
                                 expected="HTTPS subresources",
                                 evidence={"resource_count": len(parser.resources)})]


def analyze_cache(headers, page_url):
    cache = _header(headers, "cache-control")
    pragma = _header(headers, "pragma")
    expires = _header(headers, "expires")
    path = urlparse(page_url).path.lower()
    sensitive = bool(re.search(r"(login|signin|account|profile|checkout|payment|admin|password|token)", path)) or bool(_header(headers, "set-cookie"))
    observed = {"cache_control": cache, "pragma": pragma, "expires": expires}
    if not sensitive:
        return [_finding("cache_policy", "Cache policy", status="NOT_APPLICABLE",
                         observed=observed,
                         expected="Policy appropriate to content sensitivity",
                         evidence=observed,
                         limitation="The page did not present a strong sensitivity signal from URL or response cookies.")]
    directives = {x.split("=", 1)[0].strip().lower() for x in str(cache or "").split(",")}
    if "no-store" in directives:
        status, severity = "PASS", "INFO"
    elif "public" in directives or (cache and "private" not in directives):
        status, severity = "WARNING", "HIGH"
    else:
        status, severity = "WARNING", "MEDIUM"
    return [_finding("cache_policy", "Sensitive-page cache policy", status=status, severity=severity,
                     observed=observed,
                     expected="no-store for responses containing sensitive or session data",
                     impact="Shared caches may retain or serve sensitive response content.",
                     remediation="Use no-store for sensitive responses and review intermediary cache behavior.",
                     evidence=observed,
                     limitation="Sensitivity was inferred from URL and Set-Cookie; response body semantics were not classified.")]


def analyze_permissions_policy(headers):
    value = _header(headers, "permissions-policy")
    if value is None:
        return [_finding("permissions_policy", "Permissions-Policy", status="NOT_APPLICABLE",
                         observed="header missing",
                         expected="A deliberate policy where browser capabilities need restriction",
                         limitation="Missing policy is not automatically a vulnerability.")]
    invalid, wild = [], []
    for directive in str(value).split(","):
        match = re.match(r"^\s*([a-zA-Z0-9-]+)(?:\s+|=|$)", directive)
        name = match.group(1) if match else directive.strip()
        if not match:
            invalid.append(name)
        if "*" in directive and name.lower() in {"camera", "microphone", "geolocation", "payment", "usb", "fullscreen"}:
            wild.append(name)
    if invalid:
        return [_finding("permissions_policy", "Invalid Permissions-Policy syntax",
                         status="FAIL", severity="MEDIUM", observed=value,
                         expected="Valid directive names and origins",
                         remediation="Correct the directive syntax and validate against supported browser directives.")]
    return [_finding("permissions_policy", "Permissions-Policy",
                     status="WARNING" if wild else "PASS",
                     severity="MEDIUM" if wild else "INFO",
                     observed=value, expected="Least-privilege capability policy",
                     impact="Wildcard access for sensitive browser capabilities broadens feature availability.",
                     remediation="Restrict sensitive capabilities to required origins.",
                     evidence={"wildcard_sensitive_directives": wild},
                     limitation="Browser support for individual directives varies.")]


def analyze_cross_origin_policies(headers):
    results = []
    specs = {
        "cross-origin-opener-policy": ({"unsafe-none", "same-origin-allow-popups", "same-origin"}, "COOP"),
        "cross-origin-embedder-policy": ({"unsafe-none", "require-corp", "credentialless"}, "COEP"),
        "cross-origin-resource-policy": ({"same-site", "same-origin", "cross-origin"}, "CORP"),
    }
    for header, (allowed, label) in specs.items():
        value = _header(headers, header)
        identifier = header.replace("-", "_")
        if value is None:
            results.append(_finding(identifier, label, status="NOT_APPLICABLE",
                                    observed="header missing",
                                    expected="A deliberate policy where cross-origin isolation is required",
                                    limitation="Missing policy is not automatically a vulnerability; compatibility requirements were not supplied."))
        elif str(value).strip().lower() not in allowed:
            results.append(_finding(identifier, f"Invalid {label} value", status="FAIL",
                                    severity="MEDIUM", observed=value, expected=sorted(allowed),
                                    remediation=f"Use a standards-compliant {label} directive."))
        else:
            results.append(_finding(identifier, label, status="PASS", observed=value,
                                    expected="Valid policy value",
                                    evidence={"header": header, "value": value},
                                    limitation="Policy compatibility depends on application embedding and resource behavior."))
    return results


def analyze_response(headers, body, page_url):
    findings = []
    cookie_findings = analyze_cookies(headers, page_url)
    for finding in cookie_findings:
        finding["category"] = "COOKIES"
    findings.extend(cookie_findings)
    findings.extend(analyze_cors(headers))
    findings.extend(analyze_mixed_content(body, page_url))
    findings.extend(analyze_cache(headers, page_url))
    findings.extend(analyze_permissions_policy(headers))
    findings.extend(analyze_cross_origin_policies(headers))
    return {"findings": findings, "cookie_count": len(_cookie_headers(headers)),
            "cors_observed": _header(headers, "access-control-allow-origin") is not None}
