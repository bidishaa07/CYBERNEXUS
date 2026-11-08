"""Phase 5.3 HSTS, redirect, disclosure and certificate evidence checks."""
import re
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import parse_qs, quote, urlparse
import httpx
from backend.app.core.config import settings


def _finding(check, title, *, status="UNKNOWN", severity="INFO", confidence="HIGH",
             observed=None, expected=None, impact="", remediation="", evidence=None,
             limitation=""):
    return {"category": "HTTP", "check_identifier": check, "title": title,
            "status": status, "severity": severity, "confidence": confidence,
            "observed_value": observed, "expected_value": expected,
            "impact": impact, "remediation": remediation, "evidence": evidence or {},
            "limitation": limitation}


def _value(headers, name):
    value = (headers or {}).get(name.lower())
    return value[-1] if isinstance(value, list) else value


@lru_cache(maxsize=512)
def check_hsts_preload(domain):
    """Query Chromium's official preload status API; never infer membership."""
    try:
        url = settings.hsts_preload_api_url.format(domain=quote(domain, safe=""))
        response = httpx.get(url, timeout=settings.hsts_preload_timeout_seconds,
                             follow_redirects=False, headers={"Accept": "application/json"})
        if response.status_code != 200:
            return {"status": "UNAVAILABLE", "http_status": response.status_code}
        data = response.json()
        state = str(data.get("status") or data.get("state") or "unknown").lower()
        return {"status": "PRELOADED" if state == "preloaded" else state.upper(), "response": data}
    except Exception as exc:
        return {"status": "UNAVAILABLE", "error": type(exc).__name__}


def _hsts(value, page_url):
    if not page_url.lower().startswith("https://"):
        return {"quality": "UNKNOWN", "status": "NOT_APPLICABLE", "directives": {},
                "explanation": "HSTS is only effective when delivered over HTTPS."}
    if not value:
        return {"quality": "MISSING", "status": "WARNING", "directives": {},
                "explanation": "No Strict-Transport-Security header was observed on the HTTPS response."}
    pieces = [item.strip() for item in str(value).split(";") if item.strip()]
    directives = {}
    duplicates = []
    for piece in pieces:
        name, _, argument = piece.partition("=")
        key = name.strip().lower()
        if key in directives:
            duplicates.append(key)
        directives[key] = argument.strip() if _ else True
    max_age = directives.get("max-age")
    errors = []
    try:
        max_age_int = int(max_age)
        if max_age_int < 0: raise ValueError
    except (TypeError, ValueError):
        max_age_int = None
        errors.append("max-age must be a non-negative integer")
    unknown = sorted(set(directives) - {"max-age", "includesubdomains", "preload"})
    if duplicates: errors.append("duplicate HSTS directives: " + ", ".join(duplicates))
    if unknown: errors.append("unknown directives: " + ", ".join(unknown))
    if errors or max_age_int is None:
        return {"quality": "MISCONFIGURED", "status": "FAIL", "directives": directives, "errors": errors}
    include = "includesubdomains" in directives
    preload = "preload" in directives
    if max_age_int >= 31536000 and include and preload: quality = "STRONG"
    elif max_age_int >= 15552000 and include: quality = "ACCEPTABLE"
    elif max_age_int > 0: quality = "WEAK"
    else: quality = "MISCONFIGURED"
    return {"quality": quality, "status": "PASS" if quality in {"STRONG", "ACCEPTABLE"} else "WARNING",
            "directives": directives, "max_age": max_age_int,
            "preload_eligible": preload and max_age_int >= 31536000 and include,
            "explanation": "Preload eligibility is not evidence that the domain is included in a browser preload list."}


def analyze_hsts(headers, page_url, observations=None, preload_status=None):
    observations = observations or []
    raw_header = (headers or {}).get("strict-transport-security")
    raw_header = "; ".join(raw_header) if isinstance(raw_header, list) else raw_header
    current = _hsts(raw_header, page_url)
    values = [((item.get("headers") or {}).get("strict-transport-security"), item.get("url"))
              for item in observations if str(item.get("url", "")).lower().startswith("https://")]
    values = [(("; ".join(value) if isinstance(value, list) else value), url) for value, url in values]
    observed_values = [value for value, _ in values if value]
    inconsistent = len(set(map(str, observed_values))) > 1
    if inconsistent and current["status"] != "FAIL":
        current["quality"] = "WEAK"
        current["status"] = "WARNING"
        current["errors"] = ["HSTS directives differ across observed HTTPS responses"]
    if current.get("preload_eligible") and preload_status is not None:
        current["preload_status"] = preload_status.get("status", "UNKNOWN")
        current["preload_evidence"] = preload_status
    current["observed_across_responses"] = [{"url": url, "header": value} for value, url in values]
    severity = "HIGH" if current["quality"] == "MISCONFIGURED" else "MEDIUM" if current["quality"] == "MISSING" else "LOW" if current["quality"] == "WEAK" else "INFO"
    status = "FAIL" if current["quality"] == "MISCONFIGURED" else "WARNING" if current["quality"] in {"MISSING", "WEAK"} else "PASS" if current["quality"] in {"STRONG", "ACCEPTABLE"} else "UNKNOWN"
    return {"quality": current["quality"], "details": current,
            "finding": _finding("hsts_quality", "HSTS quality",
                                 status=status, severity=severity,
                                 observed=current, expected="Valid HTTPS HSTS with an appropriate max-age",
                                 impact="Weak or invalid HSTS reduces protection against downgrade and first-visit interception.",
                                 remediation="Publish a valid Strict-Transport-Security policy appropriate to the domain and deployment.",
                                 evidence={"responses": current.get("observed_across_responses", [])},
                                 limitation=current.get("explanation", "") + " HSTS behavior was assessed only across responses observed by this scan.")}


def analyze_redirect_chain(original_url, http_result, max_hops=5):
    hops = http_result.get("redirects") or []
    errors = list(http_result.get("errors") or [])
    errors.extend(http_result.get("unavailable") or [])
    findings = []
    original_host = (urlparse(original_url).hostname or "").lower().rstrip(".")
    open_redirect_indicators = []
    for hop in hops:
        source = hop.get("source_domain") or (urlparse(hop.get("source_url", "")).hostname or "")
        destination = hop.get("destination_domain") or (urlparse(hop.get("destination_url", "")).hostname or "")
        if hop.get("https_downgrade"):
            findings.append(_finding(f"redirect_{hop.get('sequence')}_https_downgrade", "HTTPS-to-HTTP redirect downgrade",
                                     status="FAIL", severity="HIGH", observed=hop,
                                     expected="Redirects should preserve HTTPS",
                                     impact="The destination is reached over unencrypted HTTP.",
                                     remediation="Redirect directly to an HTTPS destination.",
                                     evidence={"hop": hop}))
        if source and destination and source.rstrip(".").lower() != destination.rstrip(".").lower():
            findings.append(_finding(f"redirect_{hop.get('sequence')}_domain_change", "Cross-domain redirect",
                                     status="WARNING", severity="LOW", observed={"source": source, "destination": destination},
                                     expected="An intentional and user-visible domain transition",
                                     impact="Users may be sent to a different security and ownership boundary.",
                                     remediation="Review the destination and document intentional cross-domain transitions.",
                                     evidence={"hop": hop},
                                     limitation="A cross-domain redirect alone is not evidence of maliciousness."))
        query = parse_qs(urlparse(hop.get("source_url", "")).query)
        redirect_parameters = sorted(set(query) & {"url", "uri", "next", "redirect", "redirect_url", "return", "return_url", "continue", "target", "dest", "destination"})
        if redirect_parameters and source and destination and source.rstrip(".").lower() != destination.rstrip(".").lower():
            open_redirect_indicators.append({"sequence": hop.get("sequence"), "parameters": redirect_parameters, "source": hop.get("source_url"), "destination": hop.get("destination_url")})
            findings.append(_finding(f"redirect_{hop.get('sequence')}_open_redirect_indicator", "Possible open-redirect indicator",
                                     status="WARNING", severity="MEDIUM", observed={"parameters": redirect_parameters, "destination": hop.get("destination_url")},
                                     expected="Redirect parameters constrained to approved destinations",
                                     impact="A user-controlled destination parameter can enable misleading external redirects if insufficiently validated.",
                                     remediation="Allowlist redirect destinations and validate them server-side.",
                                     evidence={"hop": hop, "parameters": redirect_parameters},
                                     limitation="This is a passive indicator from an observed redirect; no attacker-controlled probe was sent and exploitability is unconfirmed."))
    if len(hops) > max_hops or "Maximum redirect depth exceeded" in errors:
        findings.append(_finding("redirect_chain_depth", "Excessive redirect chain",
                                 status="FAIL", severity="MEDIUM", observed=len(hops),
                                 expected=f"At most {max_hops} redirects",
                                 impact="Long chains increase latency and make the final destination harder to verify.",
                                 remediation="Reduce redirects and remove unnecessary intermediary destinations."))
    if any("loop" in str(error).lower() for error in errors):
        findings.append(_finding("redirect_loop", "Redirect loop detected", status="FAIL", severity="HIGH",
                                 observed=errors, expected="A terminating redirect chain",
                                 impact="The requested resource cannot be reached reliably.",
                                 remediation="Remove the circular redirect rule.", evidence={"errors": errors}))
    if any("location" in str(error).lower() or "destination" in str(error).lower() for error in errors):
        findings.append(_finding("redirect_chain_error", "Invalid or incomplete redirect",
                                 status="UNKNOWN", severity="MEDIUM", observed=errors,
                                 expected="Valid Location headers and safe destinations",
                                 impact="The complete redirect chain could not be verified.",
                                 remediation="Return a valid Location header and ensure the target is reachable.",
                                 limitation="The scanner stopped safely and did not follow an invalid or restricted destination.",
                                 evidence={"errors": errors}))
    final_url = http_result.get("final_url") or (hops[-1].get("destination_url") if hops else original_url)
    report = {"original_url": original_url, "final_destination": final_url,
              "redirect_count": len(hops), "hops": hops, "errors": errors,
              "loop_detected": any("loop" in str(error).lower() for error in errors),
              "complete": bool(http_result.get("complete") and not errors),
              "open_redirect_verification": {"status": "INDICATOR_ONLY" if open_redirect_indicators else "NOT_OBSERVED",
                  "indicators": open_redirect_indicators,
                  "reason": "No arbitrary attacker-controlled redirect parameter was tested."}}
    return {"report": report, "findings": findings}


def analyze_disclosure(headers):
    details = {}
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-runtime", "x-drupal-cache", "via"):
        value = _value(headers, name)
        if value:
            details[name] = value
    if not details:
        return {"details": {}, "finding": _finding("server_disclosure", "Server technology disclosure",
                                                     status="PASS", observed="No common disclosure headers observed",
                                                     expected="Minimal response metadata")}
    versioned = any(re.search(r"\d+(?:\.\d+){1,}", str(value)) for value in details.values())
    advisory = lookup_disclosure_advisories(tuple(sorted((str(key), str(value)) for key, value in details.items())))
    advisory_status = advisory.get("status")
    title = "Server technology disclosure"
    status = "WARNING"
    severity = "LOW" if not versioned else "MEDIUM"
    if advisory_status == "MATCHES":
        title = "Server disclosure with advisory matches"
        severity = "MEDIUM"
    elif advisory_status == "UNAVAILABLE":
        title = "Server disclosure; advisory lookup unavailable"
    finding = _finding(
        "server_disclosure", "Server technology disclosure",
        status=status, severity=severity,
        observed=details, expected="Minimal server metadata without unnecessary version detail",
        impact="Detailed technology metadata can help fingerprint the deployment.",
        remediation="Remove or minimize unnecessary Server, X-Powered-By and framework version headers.",
        evidence={"headers": details, "advisories": advisory},
        limitation="Disclosure alone does not establish a vulnerability. Advisory matches are potential evidence only and were not validated by exploitation.")
    finding["title"] = title
    return {"details": details, "advisories": advisory, "finding": finding}


@lru_cache(maxsize=256)
def lookup_disclosure_advisories(details_key):
    """Cautiously correlate known product/version strings with NVD results.

    A keyword hit is reported as a potential advisory match, never as proof
    that the observed deployment is vulnerable.
    """
    if not settings.disclosure_vulnerability_lookup_enabled:
        return {"status": "NOT_CONFIGURED", "matches": []}
    details = dict(details_key)
    candidates = []
    for value in details.values():
        match = re.search(r"(?i)(nginx|apache(?: httpd)?|node(?:\.js)?|tomcat|iis|php)[ /_-]*([0-9]+(?:\.[0-9]+){1,3})", str(value))
        if match:
            candidates.append((match.group(1).lower(), match.group(2), str(value)))
    if not candidates:
        return {"status": "NOT_SUPPORTED", "matches": []}
    product, version, observed = candidates[0]
    try:
        response = httpx.get(settings.nvd_api_url,
                             params={"keywordSearch": f"{product} {version}", "resultsPerPage": 10},
                             timeout=settings.nvd_timeout_seconds,
                             headers={"Accept": "application/json", "User-Agent": "DigitalTrustIntelligence/1.0"})
        if response.status_code == 429:
            return {"status": "RATE_LIMITED", "matches": []}
        if response.status_code >= 500:
            return {"status": "UNAVAILABLE", "http_status": response.status_code, "matches": []}
        if response.status_code != 200:
            return {"status": "PROVIDER_ERROR", "http_status": response.status_code, "matches": []}
        data = response.json()
        matches = []
        for item in data.get("vulnerabilities", [])[:10]:
            cve = item.get("cve") or {}
            descriptions = " ".join(str(x.get("value", "")) for x in cve.get("descriptions", []))
            if product in descriptions.lower() and version.lower() in descriptions.lower():
                matches.append({"id": cve.get("id"), "published": cve.get("published"),
                                "last_modified": cve.get("lastModified"),
                                "matched_product": product, "matched_version": version,
                                "description_match": True})
        return {"status": "MATCHES" if matches else "NO_MATCH", "product": product,
                "version": version, "observed": observed, "matches": matches}
    except Exception as exc:
        return {"status": "UNAVAILABLE", "error": type(exc).__name__, "matches": []}


def analyze_tls_report(host, certificate):
    certificate = certificate or {}
    validation = certificate.get("validation") or {}
    tls = certificate.get("tls_configuration") or {}
    leaf = certificate.get("certificate") or {}
    findings = []
    validation_status = str(validation.get("status") or certificate.get("status") or "UNKNOWN").upper()
    if validation_status == "VALID":
        findings.append(_finding("tls_certificate_validation", "Certificate path validation", status="PASS",
                                 observed=validation_status, expected="Cryptographically validated trusted path",
                                 evidence=validation))
    elif validation_status in {"INVALID", "UNTRUSTED", "EXPIRED", "NOT_YET_VALID"}:
        findings.append(_finding("tls_certificate_validation", "Certificate path validation", status="FAIL",
                                 severity="HIGH", observed=validation_status, expected="Cryptographically validated trusted path",
                                 impact="The certificate path cannot establish the expected TLS identity.",
                                 remediation="Deploy a valid certificate chain anchored in the configured trust store.",
                                 evidence=validation))
    else:
        findings.append(_finding("tls_certificate_validation", "Certificate path validation", status="UNKNOWN",
                                 severity="MEDIUM", observed=validation_status, expected="Cryptographically validated trusted path",
                                 limitation="Certificate validation could not be completed; this is not a valid or safe result.",
                                 evidence=validation))
    san = (tls.get("san_validation") or {})
    san_status = str(san.get("status") or "UNKNOWN").upper()
    findings.append(_finding("tls_hostname_san", "TLS hostname and SAN validation",
                             status="PASS" if san_status == "VALID" else "FAIL" if san_status in {"MISMATCH", "MISSING_SAN"} else "UNKNOWN",
                             severity="HIGH" if san_status in {"MISMATCH", "MISSING_SAN"} else "INFO",
                             observed=san, expected=f"SAN matching requested hostname {host}",
                             impact="A SAN mismatch prevents reliable hostname identity validation.",
                             remediation="Issue a certificate containing the exact hostname or a valid matching wildcard SAN.",
                             evidence=san, limitation="Common Name is not used as a modern SAN fallback."))
    grade = tls.get("overall_grade") or "UNKNOWN"
    findings.append(_finding("tls_configuration_grade", "TLS configuration grade",
                             status="PASS" if grade in {"A", "B"} else "WARNING" if grade in {"C", "D", "F"} else "UNKNOWN",
                             severity="MEDIUM" if grade in {"D", "F"} else "LOW" if grade == "C" else "INFO",
                             observed={"grade": grade, "version": tls.get("version_security"), "cipher": tls.get("cipher_security")},
                             expected="Modern protocol and cipher configuration",
                             impact="Deprecated protocols or weak ciphers reduce transport security.",
                             remediation="Disable deprecated TLS versions and weak cipher suites.",
                             evidence=tls,
                             limitation=tls.get("explanation", "TLS grading depends on the completed handshake probes.")))
    if leaf:
        findings.append(_finding("tls_certificate_metadata", "TLS certificate metadata",
                                 status="PASS", observed={"issuer": leaf.get("issuer"), "not_after": leaf.get("not_after"),
                                                           "signature_algorithm": leaf.get("signature_algorithm"),
                                                           "public_key_algorithm": leaf.get("public_key_algorithm"),
                                                           "public_key_size": leaf.get("public_key_size")},
                                 expected="Available certificate metadata", evidence={"leaf": leaf},
                                 limitation="Metadata availability is not itself proof of a secure deployment."))
    if tls.get("status") == "ANALYZED":
        status = "COMPLETED"
    elif leaf or validation:
        status = "PARTIAL"
    else:
        status = "UNKNOWN"
    return {"findings": findings, "status": status,
            "limitation": "Certificate metadata may be available even when complete TLS handshake or path validation could not be completed."}
