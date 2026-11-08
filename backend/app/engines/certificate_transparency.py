"""Certificate Transparency history normalization and conservative anomaly detection."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
from backend.app.core.config import settings

def _now(): return datetime.now(timezone.utc).isoformat()
def _date(value):
    try: return datetime.fromisoformat(str(value).replace("Z","+00:00")).isoformat()
    except (TypeError,ValueError): return None
def _names(value):
    values=[]
    for item in str(value or "").replace(",","\n").splitlines():
        item=item.strip().lower().rstrip(".")
        if item and item not in values: values.append(item)
    return sorted(values)

def _normalize(item: dict) -> dict | None:
    if not isinstance(item,dict): return None
    domains=_names(item.get("name_value") or item.get("san") or item.get("subject_alt_names"))
    return {"certificate_id":item.get("id") or item.get("cert_id"),"fingerprint_sha256":item.get("sha256") or item.get("fingerprint_sha256") or item.get("fingerprint"),"issuer":item.get("issuer_name") or item.get("issuer"),"subject":item.get("common_name") or item.get("subject"),"san_domains":domains,"serial_number":str(item.get("serial_number")) if item.get("serial_number") is not None else None,"not_before":_date(item.get("not_before")),"not_after":_date(item.get("not_after")),"observation_timestamp":_date(item.get("entry_timestamp") or item.get("min_entry_timestamp") or item.get("observed_at")) or _now(),"ct_log":item.get("ct_log") or item.get("log_id") or item.get("log_name"),"issuer_ca_id":item.get("issuer_ca_id"),"source":"crt.sh","status":item.get("status") or "OBSERVED"}

def detect_anomalies(domain: str, records: list[dict], ca_records: list[dict] | None = None) -> list[dict]:
    ordered=sorted(records,key=lambda x:(x.get("not_before") or "",x.get("observation_timestamp") or "")); findings=[]; previous=None; issuers={}
    for record in ordered:
        issuer=record.get("issuer") or "UNKNOWN"; issuers[issuer]=issuers.get(issuer,0)+1
        if record.get("fingerprint_sha256") and sum(1 for item in records if item.get("fingerprint_sha256")==record.get("fingerprint_sha256"))>1:
            findings.append({"finding_type":"duplicate_certificate_observation","fingerprint":record.get("fingerprint_sha256"),"domain":domain,"issuer":issuer,"source":"crt.sh","observation_timestamp":record.get("observation_timestamp"),"confidence":"medium","evidence":{"certificate_id":record.get("certificate_id")},"explanation":"The same certificate fingerprint was observed in multiple CT response entries; this may reflect duplicate logging rather than malicious issuance."})
        wildcards=[name for name in record.get("san_domains",[]) if name.startswith("*.")]
        if wildcards:
            findings.append({"finding_type":"wildcard_certificate_observed","fingerprint":record.get("fingerprint_sha256"),"domain":domain,"issuer":issuer,"source":"crt.sh","observation_timestamp":record.get("observation_timestamp"),"confidence":"low","evidence":{"wildcard_sans":wildcards},"explanation":"A wildcard SAN was observed in CT. Wildcard issuance is not inherently malicious and requires ownership context."})
        if previous:
            if previous.get("issuer") and issuer != previous.get("issuer"):
                findings.append({"finding_type":"issuer_change","fingerprint":record.get("fingerprint_sha256"),"domain":domain,"issuer":issuer,"source":"crt.sh","observation_timestamp":record.get("observation_timestamp"),"confidence":"low","evidence":{"previous_issuer":previous.get("issuer"),"current_issuer":issuer},"explanation":"The observed issuer changed across certificate history; certificate renewal or CA migration can explain this."})
            added=sorted(set(record.get("san_domains",[]))-set(previous.get("san_domains",[])))
            if added:
                findings.append({"finding_type":"san_addition","fingerprint":record.get("fingerprint_sha256"),"domain":domain,"issuer":issuer,"source":"crt.sh","observation_timestamp":record.get("observation_timestamp"),"confidence":"low","evidence":{"added_sans":added,"previous_sans":previous.get("san_domains",[])},"explanation":"New SAN names appeared compared with the previous observed certificate; this is an observation, not proof of unauthorized issuance."})
        previous=record
    if len(issuers)>1:
        findings.append({"finding_type":"multiple_issuers_observed","fingerprint":None,"domain":domain,"issuer":None,"source":"crt.sh","observation_timestamp":_now(),"confidence":"low","evidence":{"issuers":sorted(issuers)},"explanation":"More than one issuer appears in the observed CT history."})
    for ca in ca_records or []:
        if str(ca.get("ca_reputation","")).upper() in {"COMPROMISED","COMPROMISED_OR_DISTRUSTED","DISTRUSTED","REVOKED"}:
            findings.append({"finding_type":"distrusted_or_compromised_ca","fingerprint":ca.get("fingerprint_sha256"),"domain":domain,"issuer":ca.get("issuer"),"source":ca.get("source"),"observation_timestamp":ca.get("checked_at") or _now(),"confidence":"high","evidence":ca,"explanation":"The associated CA evidence is explicitly marked compromised or distrusted by a configured trust source."})
    return findings

def analyze(domain: str, client=None) -> dict:
    url=settings.crtsh_api_url.format(domain=domain)
    result={"status":"UNAVAILABLE","source":"crt.sh","query":url,"checked_at":_now(),"records":[],"timeline":[],"anomalies":[],"errors":[]}
    try:
        requester=client or httpx
        response=requester.get(url,timeout=8)
        if response.status_code!=200: result["errors"].append(f"http_{response.status_code}"); return result
        if "json" not in response.headers.get("content-type","").lower(): result["errors"].append("content_type_not_json"); return result
        payload=response.json()
        if not isinstance(payload,list): result["errors"].append("response_not_array"); return result
        records=[item for item in (_normalize(value) for value in payload) if item]
        result["records"]=records; result["timeline"]=sorted(records,key=lambda x:(x.get("not_before") or "",x.get("observation_timestamp") or "")); result["anomalies"]=detect_anomalies(domain,records); result["status"]="AVAILABLE"; result["record_count"]=len(records); return result
    except (httpx.TimeoutException,TimeoutError): result["errors"].append("timeout")
    except (httpx.NetworkError,OSError): result["errors"].append("network_error")
    except Exception as exc: result["errors"].append(type(exc).__name__)
    return result
