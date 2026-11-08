from __future__ import annotations
import hashlib, secrets
from datetime import datetime, timedelta, timezone
import dns.resolver
from backend.app.engines.safe_http import fetch as safe_fetch

def create_challenge(db, model, brand_id: int, domain: str, method: str):
    if method not in {"dns_txt","http_well_known"}: raise ValueError("Unsupported verification method")
    token=secrets.token_urlsafe(32); now=datetime.now(timezone.utc); path=f"/.well-known/digital-trust-verification/{secrets.token_hex(8)}"
    row=model(brand_id=brand_id,domain=domain.lower().rstrip("."),method=method,token_hash=hashlib.sha256(token.encode()).hexdigest(),challenge_path=path,status="pending",created_at=now,expires_at=now+timedelta(minutes=30))
    db.add(row); db.commit(); db.refresh(row)
    return row, token

def _finish(db, challenge, brand, evidence_model, audit_model, ok: bool, reason: str):
    now=datetime.now(timezone.utc); challenge.status="verified" if ok else "rejected"; challenge.verified_at=now if ok else None
    if ok:
        brand.verification_status="verified"; brand.verification_date=now
        db.add(evidence_model(brand_id=brand.id,evidence_type=challenge.method,evidence_value=challenge.domain,source="challenge verification",status="verified",checked_at=now))
    db.add(audit_model(brand_id=brand.id,actor="admin",action="challenge_verified" if ok else "challenge_rejected",details_json=str({"method":challenge.method,"domain":challenge.domain,"reason":reason})))
    db.commit(); return {"status":challenge.status,"challenge_id":challenge.id,"domain":challenge.domain,"method":challenge.method,"reason":reason,"verified_at":challenge.verified_at}

def verify(db, challenge, brand, evidence_model, audit_model):
    now=datetime.now(timezone.utc)
    if challenge.status != "pending": return {"status":challenge.status,"challenge_id":challenge.id,"reason":"challenge_not_pending"}
    if challenge.expires_at.replace(tzinfo=timezone.utc) < now:
        challenge.status="expired"; db.commit(); return {"status":"expired","challenge_id":challenge.id}
    try:
        if challenge.method == "dns_txt":
            answers=dns.resolver.resolve(challenge.domain,"TXT"); values=[part.decode() if isinstance(part,bytes) else str(part).strip('"') for answer in answers for part in answer.strings]
            ok=any(hashlib.sha256(value.encode()).hexdigest()==challenge.token_hash for value in values); reason="exact DNS TXT challenge token" if ok else "challenge token not found"
        else:
            if not challenge.domain or "." not in challenge.domain: return _finish(db,challenge,brand,evidence_model,audit_model,False,"invalid domain")
            response=safe_fetch("https://"+challenge.domain+challenge.challenge_path,max_bytes=4096)
            value=response.body.decode("utf-8","replace").strip(); ok=response.status_code==200 and hashlib.sha256(value.encode()).hexdigest()==challenge.token_hash; reason="exact HTTPS well-known challenge token" if ok else "challenge token not found"
        return _finish(db,challenge,brand,evidence_model,audit_model,ok,reason)
    except Exception as exc:
        return _finish(db,challenge,brand,evidence_model,audit_model,False,type(exc).__name__)
