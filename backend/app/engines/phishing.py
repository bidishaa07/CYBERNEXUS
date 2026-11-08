import re
from urllib.parse import urlparse

BRANDS = {"google", "microsoft", "apple", "paypal", "amazon", "facebook", "instagram", "netflix", "github", "bank"}
SUSPICIOUS_TLDS = {"zip", "top", "click", "work", "country", "gq", "tk", "xyz"}

def analyze(url: str, domain: str):
    parsed = urlparse(url); labels = domain.split("."); host = domain.lower()
    evidence = []; score = 0
    if "@" in parsed.netloc: evidence.append(("URL contains an @ sign", "high")); score += 28
    if len(url) > 120: evidence.append(("Unusually long URL", "medium")); score += 12
    if domain.split(".")[-1] in SUSPICIOUS_TLDS: evidence.append(("Higher-risk top-level domain", "medium")); score += 10
    if host.startswith("xn--") or ".xn--" in host: evidence.append(("Punycode/homograph indicator", "high")); score += 25
    if sum(c.isdigit() for c in host) >= 4: evidence.append(("Domain has an unusual number of digits", "medium")); score += 8
    if len(labels) >= 4: evidence.append(("Deep subdomain nesting", "medium")); score += 10
    for brand in BRANDS:
        if brand in host and not (host == f"{brand}.com" or host.endswith(f".{brand}.com")):
            evidence.append((f"Possible {brand} impersonation", "high")); score += 24
    words = re.findall(r"login|signin|verify|secure|account|password|wallet|credential", (parsed.path + parsed.query).lower())
    if words: evidence.append(("Credential-harvesting language in URL", "high")); score += min(24, 8 * len(set(words)))
    return {"score": min(score, 100), "evidence": [{"message": m, "severity": s, "state": "suspicious"} for m, s in evidence], "clean_checks": ["URL syntax parsed", "Hostname normalized"]}
