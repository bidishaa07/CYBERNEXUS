from urllib.parse import urlsplit
from backend.app.engines.indicator_normalization import normalize_domain

def _canonical_domain(value):
    raw = str(value or "").strip()
    host = urlsplit(raw if "://" in raw else f"//{raw}").hostname or raw.split("/")[0]
    try:
        return normalize_domain(host)
    except ValueError:
        return host.lower().rstrip(".")

def correlate(scans, reports):
    domains={}
    for item in scans: domains.setdefault(_canonical_domain(item.domain or item.url), []).append({"type":"scan","id":item.id,"url":item.url})
    for item in reports:
        host=_canonical_domain(item.url)
        domains.setdefault(host, []).append({"type":"community_report","id":item.id,"url":item.url})
    clusters=[{"key":key,"indicators":value,"reason":"Repeated domain across submitted intelligence"} for key,value in domains.items() if len(value)>1]
    return {"clusters":clusters,"count":len(clusters),"method":"Deterministic exact-domain matching; no relationship is asserted without shared evidence."}
