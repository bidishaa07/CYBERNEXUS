"""Configured, provenance-preserving CA distrust/advisory feed adapter."""
from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from cryptography import x509
from backend.app.core.config import settings
from backend.app.engines.certificate_chain import _fingerprint
from backend.app.engines.safe_http import fetch as safe_fetch, UnsafeDestination

def _now(): return datetime.now(timezone.utc)

def _iso(value): return value.isoformat() if value else None

def _parse_date(value):
    try: return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except (TypeError, ValueError): return None

def lookup(cert: x509.Certificate, trusted_roots: list[x509.Certificate], db=None) -> dict:
    fingerprint=_fingerprint(cert); configured={item.strip().lower() for item in settings.certificate_distrust_fingerprints.split(",") if item.strip()}
    if fingerprint.lower() in configured:
        return {"status":"DISTRUSTED","ca_reputation":"COMPROMISED_OR_DISTRUSTED","source":"configured_distrust_fingerprints","effective_date":None,"evidence":["certificate_fingerprint_explicitly_distrusted"],"fingerprint_sha256":fingerprint}
    source=settings.ca_reputation_feed_url.strip()
    if not source:
        return {"status":"UNKNOWN","ca_reputation":"UNKNOWN","source":"not_configured","effective_date":None,"evidence":[],"fingerprint_sha256":fingerprint}
    now=_now()
    if db is not None:
        from backend.app.models.models import CAReputationRecord
        cached=db.query(CAReputationRecord).filter(CAReputationRecord.certificate_fingerprint==fingerprint,CAReputationRecord.source==source,CAReputationRecord.expires_at>now).first()
        if cached:
            details=json.loads(cached.details_json or "{}")
            return {"status":cached.status,"ca_reputation":details.get("ca_reputation","UNKNOWN"),"source":source,"effective_date":_iso(cached.effective_date),"evidence":details.get("evidence",[]),"fingerprint_sha256":fingerprint,"cache":"hit","checked_at":_iso(cached.checked_at)}
    try:
        response=safe_fetch(source,timeout=settings.provider_timeout_seconds,max_bytes=2*1024*1024)
        if response.status_code!=200: return {"status":"UNAVAILABLE","ca_reputation":"UNKNOWN","source":source,"error":f"http_{response.status_code}","fingerprint_sha256":fingerprint}
        payload=json.loads(response.body.decode("utf-8")); records=payload.get("records",payload) if isinstance(payload,dict) else payload
        if not isinstance(records,list): raise ValueError("feed_records_not_a_list")
        match=next((item for item in records if isinstance(item,dict) and str(item.get("fingerprint_sha256","")).lower()==fingerprint.lower()),None)
        if match:
            status=str(match.get("status","UNKNOWN")).upper(); reputation=str(match.get("ca_reputation",status if status in {"COMPROMISED","DISTRUSTED","REVOKED"} else "UNKNOWN")).upper(); effective=_parse_date(match.get("effective_date")); evidence=match.get("evidence",[])
        else:
            status="NO_MATCH"; reputation="UNKNOWN"; effective=None; evidence=["No matching certificate fingerprint in configured advisory feed"]
        result={"status":status,"ca_reputation":reputation,"source":source,"effective_date":_iso(effective),"evidence":evidence,"fingerprint_sha256":fingerprint,"cache":"miss","checked_at":_iso(now)}
        if db is not None:
            from backend.app.models.models import CAReputationRecord
            row=db.query(CAReputationRecord).filter(CAReputationRecord.certificate_fingerprint==fingerprint,CAReputationRecord.source==source).first()
            details={"ca_reputation":reputation,"evidence":evidence}
            if row: row.status=status; row.effective_date=effective; row.details_json=json.dumps(details); row.checked_at=now; row.expires_at=now+timedelta(seconds=settings.ca_reputation_feed_ttl_seconds)
            else: db.add(CAReputationRecord(certificate_fingerprint=fingerprint,status=status,source=source,effective_date=effective,details_json=json.dumps(details),checked_at=now,expires_at=now+timedelta(seconds=settings.ca_reputation_feed_ttl_seconds)))
        return result
    except (TimeoutError, OSError, UnsafeDestination) as exc:
        return {"status":"UNAVAILABLE","ca_reputation":"UNKNOWN","source":source,"error":type(exc).__name__,"fingerprint_sha256":fingerprint}
    except Exception as exc:
        return {"status":"UNKNOWN","ca_reputation":"UNKNOWN","source":source,"error":type(exc).__name__,"fingerprint_sha256":fingerprint}

def configuration_status() -> dict:
    return {"provider":"CA reputation advisory feed","configured":bool(settings.ca_reputation_feed_url.strip()),"source":settings.ca_reputation_feed_url or None,"cache_ttl_seconds":settings.ca_reputation_feed_ttl_seconds,"distrust_fingerprint_count":len([item for item in settings.certificate_distrust_fingerprints.split(",") if item.strip()])}
