"""Provider-neutral network enrichment. Missing evidence remains UNKNOWN."""
from __future__ import annotations
from datetime import datetime, timezone
import httpx
from backend.app.core.config import settings

def _now(): return datetime.now(timezone.utc).isoformat()

def lookup_ripe(ip: str) -> dict:
    try:
        response=httpx.get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=settings.ipinfo_timeout_seconds, follow_redirects=False)
        if response.status_code != 200: return {"source":"RIPE Stat","ip":ip,"status":"unavailable","http_status":response.status_code,"checked_at":_now()}
        data=response.json().get("data",{})
        return {"source":"RIPE Stat","ip":ip,"status":"queried","announced_prefix":data.get("prefix"),"asns":data.get("asns",[]),"checked_at":_now()}
    except httpx.TimeoutException: return {"source":"RIPE Stat","ip":ip,"status":"timeout","checked_at":_now()}
    except (httpx.HTTPError, OSError, ValueError, TypeError): return {"source":"RIPE Stat","ip":ip,"status":"unavailable","error":"network_or_malformed_response","checked_at":_now()}

def classify_hosting(records: list[dict]) -> dict:
    for item in records:
        explicit=item.get("classification") or item.get("hosting_classification")
        if explicit:
            return {"classification":explicit,"confidence":"medium","evidence":[{"source":item.get("source"),"field":"classification"}],"status":"available"}
    return {"classification":"Unknown","confidence":"none","evidence":[],"status":"unknown","limitation":"Configured providers did not expose a supported hosting classification."}

def enrich_record(primary: dict, fallback: dict) -> dict:
    result=dict(primary); result.setdefault("sources",[])
    if primary.get("source") and primary["source"] not in result["sources"]: result["sources"].append(primary["source"])
    if fallback.get("status") == "queried":
        result["sources"].append(fallback["source"])
        if not result.get("network_range"): result["network_range"]=fallback.get("announced_prefix")
        if not result.get("asn_number") and fallback.get("asns"): result["asn_number"]=f"AS{fallback['asns'][0]}" if not str(fallback['asns'][0]).upper().startswith("AS") else str(fallback['asns'][0]).upper()
    result["hosting_classification"]=classify_hosting([primary, fallback])
    result["provenance"]=[{"source":x,"checked_at":result.get("checked_at")} for x in result["sources"]]
    return result
