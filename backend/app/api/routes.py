import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from backend.app.db.session import get_db, SessionLocal
from backend.app.models.models import Scan, CommunityReport, DomainIntelligence, ProviderVerdict, ThreatIndicator, RedirectHop, BrandRegistry, BrandVerificationEvidence, BrandVerificationChallenge, BrandVerificationAudit, BrandLogoAsset, BrandImageReference, WebsiteImageCandidate, ImageComparison, CertificateRecord, CertificateChainLink, CertificateValidationResult, CertificateRevocationResult, CertificateRevocationJob, CertificateTransparencyEntry, CertificateTransparencyAnomaly, CertificateRiskAssessment, EmailAnalysis, EmailHeader, EmailAuthenticationResult, EmailHeaderAnomaly, EmailRawMessage, EmailSmtpContext, EmailVerificationRun, MessageAnalysisRecord, MessageIndicatorResult, MessageDomainSpoofingFinding, EmailProviderRegistry, ContactRiskAssessment, IntelligenceVerification, BackgroundTaskRun
from backend.app.schemas.schemas import ScanRequest, ReportRequest
from backend.app.services.scanner import scan
from backend.app.services.scanner import _destination_providers
from backend.app.engines.threats import check as check_threats
from backend.app.engines.domain_intelligence import collect as collect_domain_intelligence
from backend.app.engines.redirect_risk import score_redirect_chain
from backend.app.engines.risk import calculate
from backend.app.engines.infrastructure_graph import build_graph
from backend.app.engines.logo_similarity import fingerprint, compare, MAX_IMAGE_BYTES
from backend.app.engines.logo_similarity import compare_fingerprints
from backend.app.engines.brand_verification import create_challenge, verify as verify_brand_challenge
from backend.app.engines.message import analyze_message
from backend.app.engines.email_analysis import analyze_email, MAX_EMAIL_BYTES, verify_dkim_signatures, evaluate_spf_context, evaluate_dmarc_alignment
from backend.app.engines.message_intelligence import analyze_indicators
from backend.app.engines.correlation import correlate
from backend.app.engines.commitments import commitment
from backend.app.engines.ml import status as ml_status
from backend.app.services.llm import configuration_status, verify_connection as verify_llm_connection
from backend.app.core.config import settings
from backend.app.engines.contact_intelligence import phone_analysis
from backend.app.engines.email_authentication_verification import verify as verify_email_authentication
from backend.app.services.cache import health as cache_health
from backend.app.db.session import engine
from backend.app.engines.google_safe_browsing import configuration_status as google_safe_browsing_configuration, verify_connection as verify_google_safe_browsing
from backend.app.engines.virustotal import configuration_status as virustotal_configuration, lookup_url as lookup_virustotal_url, submit_url as submit_virustotal_url, poll_analysis as poll_virustotal_analysis
from backend.app.engines.external_intelligence import status as external_intelligence_status, urlhaus_status as urlhaus_connectivity_status
from backend.app.engines.certificate_chain import _trusted_roots
from backend.app.engines.certificate_revocation import analyze_chain
from backend.app.engines.ca_reputation import configuration_status as ca_reputation_configuration
from cryptography import x509

router = APIRouter()

def _refresh_revocation_job(job_id: int, scan_id: int):
    db=SessionLocal(); job=db.get(CertificateRevocationJob,job_id)
    try:
        if not job: return
        job.status="RUNNING"; job.started_at=datetime.now(timezone.utc); db.commit()
        scan_row=db.get(Scan,scan_id)
        if not scan_row: raise ValueError("scan_not_found")
        result=json.loads(scan_row.result_json); certificate=result.get("certificate",{}); items=[]
        for item in certificate.get("certificates",[]):
            if item.get("der"):
                items.append((x509.load_der_x509_certificate(bytes.fromhex(item["der"])),bytes.fromhex(item["der"])))
        refreshed=analyze_chain(items,_trusted_roots(),db) if items else {"status":"UNAVAILABLE","certificates":[]}
        certificate["revocation"]=refreshed; result["certificate"]=certificate; scan_row.result_json=json.dumps(result)
        db.query(CertificateRevocationResult).filter(CertificateRevocationResult.scan_id==scan_id).delete(synchronize_session=False)
        for item in refreshed.get("certificates",[]):
            aggregate=item.get("aggregate",{}); sources=aggregate.get("sources",{}); ca=item.get("ca_trust",{})
            db.add(CertificateRevocationResult(scan_id=scan_id,certificate_fingerprint=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),status=aggregate.get("status","UNKNOWN"),ocsp_status=(sources.get("ocsp") or {}).get("status"),crl_status=(sources.get("crl") or {}).get("status"),distrust_status=ca.get("status"),ca_reputation=ca.get("ca_reputation"),evidence_json=json.dumps(item),checked_at=datetime.now(timezone.utc)))
        job.status="COMPLETED"; job.completed_at=datetime.now(timezone.utc); db.commit()
    except Exception as exc:
        db.rollback(); job=db.get(CertificateRevocationJob,job_id)
        if job: job.status="FAILED"; job.error=type(exc).__name__; job.completed_at=datetime.now(timezone.utc); db.commit()
    finally: db.close()

def admin_only(x_admin_token: str | None = Header(default=None)):
    if x_admin_token != settings.admin_api_token: raise HTTPException(403, "Administrator token required")

@router.get("/health")
def health():
    database = "ok"
    try:
        with engine.connect() as connection: connection.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception: database = "unavailable"
    return {"status": "ok" if database == "ok" else "degraded", "service": "digital-trust-intelligence", "database": database, "cache": cache_health()}

@router.get("/intelligence/providers/health")
def intelligence_provider_health():
    phone_configured = bool((settings.phone_reputation_api_url.strip() and settings.phone_reputation_api_key.strip()) or settings.ipqualityscore_api_key.strip())
    phone_provider = "IPQualityScore Phone Validation" if settings.ipqualityscore_api_key.strip() else settings.phone_reputation_provider
    return {"phone_reputation": {"status": "CONFIGURED" if phone_configured else "NOT_CONFIGURED", "provider": phone_provider}, "cache": cache_health(), "database": {"status": "CONNECTED" if health()["database"] == "ok" else "UNAVAILABLE"}, "workers": {"status": "CONFIGURED" if settings.celery_broker_url else "NOT_CONFIGURED"}}

@router.post("/intelligence/phone/analyze")
def intelligence_phone(payload: dict, db: Session = Depends(get_db)):
    value = payload.get("phone")
    if not isinstance(value, str) or not value.strip(): raise HTTPException(400, "phone is required")
    result = phone_analysis(value.strip())
    db.add(IntelligenceVerification(indicator_type="phone", indicator=value.strip(), provider=result.get("reputation", {}).get("provider", "libphonenumber"), status=result.get("status", "UNKNOWN"), result_json=json.dumps(result), checked_at=datetime.now(timezone.utc)))
    db.commit()
    return result

@router.post("/intelligence/email/authentication")
def intelligence_email_authentication(payload: dict, db: Session = Depends(get_db)):
    email = payload.get("email")
    domain = payload.get("domain")
    if isinstance(email, str) and "@" in email: domain = email.rsplit("@", 1)[1]
    if not isinstance(domain, str) or not re.match(r"^(?=.{1,253}$)[A-Za-z0-9.-]+$", domain): raise HTTPException(400, "email or domain is required")
    raw = payload.get("raw_message")
    raw_bytes = raw.encode() if isinstance(raw, str) and raw else None
    result = verify_email_authentication(domain, payload.get("selector"), raw_bytes)
    db.add(IntelligenceVerification(indicator_type="email", indicator=domain.lower().rstrip("."), provider="DNS/email-authentication", status="COMPLETED", result_json=json.dumps(result), checked_at=datetime.now(timezone.utc)))
    db.commit()
    return result

@router.get("/intelligence/tasks/{task_id}")
def intelligence_task(task_id: str, db: Session = Depends(get_db)):
    row = db.query(BackgroundTaskRun).filter(BackgroundTaskRun.task_id == task_id).first()
    if not row: raise HTTPException(404, "Task not found")
    return {"task_id": row.task_id, "task_name": row.task_name, "status": row.status, "result": json.loads(row.result_json) if row.result_json else None, "error": row.error, "started_at": row.started_at, "completed_at": row.completed_at}

@router.get("/brands")
def brands(db: Session = Depends(get_db)):
    return [{"id":b.id,"brand_name":b.brand_name,"official_domain":b.official_domain,"official_website":b.official_website,"logo_url":b.logo_url,"verification_status":b.verification_status,"source":b.source,"source_reliability":b.source_reliability,"verification_date":b.verification_date} for b in db.query(BrandRegistry).order_by(BrandRegistry.brand_name).all()]

@router.post("/admin/brands")
def add_brand(payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    required=(payload.get("brand_name"),payload.get("official_domain"),payload.get("source"))
    if not all(isinstance(x,str) and x.strip() for x in required): raise HTTPException(400,"brand_name, official_domain and source are required")
    # A registry write never self-asserts ownership. Verification can only be
    # reached through challenge evidence or a separately reviewed record.
    row=BrandRegistry(brand_name=payload["brand_name"].strip(),official_domain=payload["official_domain"].strip().lower().rstrip("."),official_website=payload.get("official_website"),logo_url=payload.get("logo_url"),verification_status="unknown",source=payload["source"],source_reliability=payload.get("source_reliability","unknown"),verification_date=None)
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=row.id,actor="admin",action="brand_created",details_json=json.dumps({"source":row.source}))); db.commit(); db.refresh(row); return {"id":row.id,"brand_name":row.brand_name,"official_domain":row.official_domain,"verification_status":row.verification_status,"source":row.source}

@router.post("/admin/brands/{brand_id}/evidence")
def add_brand_evidence(brand_id: int, payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry, brand_id): raise HTTPException(404,"Brand not found")
    if not payload.get("evidence_type") or not payload.get("evidence_value"): raise HTTPException(400,"evidence_type and evidence_value are required")
    item=BrandVerificationEvidence(brand_id=brand_id,evidence_type=payload["evidence_type"],evidence_value=payload["evidence_value"],source=payload.get("source"),status=payload.get("status","unverified")); db.add(item); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="evidence_added",details_json=json.dumps({"evidence_type":payload["evidence_type"],"status":item.status}))); db.commit(); db.refresh(item); return {"id":item.id,"brand_id":brand_id,"status":item.status,"checked_at":item.checked_at}

@router.post("/admin/brands/{brand_id}/challenges")
def create_brand_challenge(brand_id: int, payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    brand=db.get(BrandRegistry,brand_id)
    if not brand: raise HTTPException(404,"Brand not found")
    domain=str(payload.get("domain") or brand.official_domain).strip().lower().rstrip(".")
    try: row,token=create_challenge(db,BrandVerificationChallenge,brand_id,domain,str(payload.get("method","dns_txt")))
    except ValueError as exc: raise HTTPException(400,str(exc))
    return {"challenge_id":row.id,"domain":domain,"method":row.method,"token":token,"dns_txt_name":domain,"dns_txt_value":token,"http_path":row.challenge_path,"expires_at":row.expires_at}

@router.post("/admin/brand-challenges/{challenge_id}/verify")
def verify_brand_challenge_route(challenge_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    challenge=db.get(BrandVerificationChallenge,challenge_id)
    if not challenge: raise HTTPException(404,"Challenge not found")
    brand=db.get(BrandRegistry,challenge.brand_id)
    return verify_brand_challenge(db,challenge,brand,BrandVerificationEvidence,BrandVerificationAudit)

@router.get("/admin/brands/{brand_id}/audit")
def brand_audit(brand_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    return [{"id":x.id,"actor":x.actor,"action":x.action,"details":json.loads(x.details_json or "{}"),"created_at":x.created_at} for x in db.query(BrandVerificationAudit).filter(BrandVerificationAudit.brand_id==brand_id).order_by(BrandVerificationAudit.created_at.desc()).all()]

@router.post("/admin/brands/import")
def import_brands(payload: dict, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    records=payload.get("records")
    if not isinstance(records,list): raise HTTPException(400,"records must be a list")
    created=[]
    for item in records:
        if not isinstance(item,dict) or not item.get("brand_name") or not item.get("official_domain") or not item.get("source"): continue
        row=BrandRegistry(brand_name=str(item["brand_name"]).strip(),official_domain=str(item["official_domain"]).lower().strip().rstrip("."),official_website=item.get("official_website"),logo_url=item.get("logo_url"),verification_status="unknown",source=item["source"],source_reliability=item.get("source_reliability","unknown")); db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=row.id,actor="admin",action="brand_imported",details_json=json.dumps({"source":row.source}))); created.append(row.id)
    db.commit(); return {"created":created,"count":len(created),"note":"Imported records remain UNKNOWN until authoritative evidence is verified."}

@router.post("/admin/brands/{brand_id}/logos")
async def upload_brand_logo(brand_id: int, file: UploadFile = File(...), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    allowed={"image/png","image/jpeg","image/webp","image/svg+xml","application/svg+xml"}
    if file.content_type not in allowed: raise HTTPException(400,"Unsupported image content type")
    data=await file.read(MAX_IMAGE_BYTES+1)
    info=fingerprint(data)
    if len(data)>MAX_IMAGE_BYTES or info.get("status")!="available": raise HTTPException(400,info.get("reason","invalid_image"))
    row=BrandLogoAsset(brand_id=brand_id,original_source=file.filename,content_type=file.content_type,width=info["width"],height=info["height"],phash=info["phash"],image_bytes=data,approval_status="pending",source="admin upload")
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="logo_uploaded",details_json=json.dumps({"logo_id":row.id}))); db.commit(); db.refresh(row)
    return {"id":row.id,"brand_id":brand_id,"approval_status":row.approval_status,"width":row.width,"height":row.height,"phash":row.phash}

@router.post("/admin/logos/{logo_id}/approve")
def approve_brand_logo(logo_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(BrandLogoAsset,logo_id)
    if not row: raise HTTPException(404,"Logo not found")
    row.approval_status="approved"; row.approved_at=datetime.now(timezone.utc); db.add(BrandVerificationAudit(brand_id=row.brand_id,actor="admin",action="logo_approved",details_json=json.dumps({"logo_id":row.id}))); db.commit(); return {"id":row.id,"approval_status":row.approval_status,"approved_at":row.approved_at}

@router.post("/admin/brands/{brand_id}/image-references")
async def upload_image_reference(brand_id: int, asset_type: str, file: UploadFile = File(...), _: None = Depends(admin_only), db: Session = Depends(get_db)):
    if asset_type not in {"logo","favicon"}: raise HTTPException(400,"asset_type must be logo or favicon")
    if not db.get(BrandRegistry,brand_id): raise HTTPException(404,"Brand not found")
    if file.content_type not in {"image/png","image/jpeg","image/webp","image/svg+xml","application/svg+xml","image/x-icon"}: raise HTTPException(400,"Unsupported image content type")
    data=await file.read(MAX_IMAGE_BYTES+1); info=fingerprint(data)
    if len(data)>MAX_IMAGE_BYTES or info.get("status")!="available": raise HTTPException(400,info.get("reason","invalid_image"))
    row=BrandImageReference(brand_id=brand_id,asset_type=asset_type,original_source=file.filename,content_type=file.content_type,width=info.get("width"),height=info.get("height"),sha256=info["sha256"],phash=info["phash"],dhash=info.get("dhash"),ahash=info.get("ahash"),image_bytes=data,approval_status="pending",source="admin image reference upload")
    db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=brand_id,actor="admin",action="image_reference_uploaded",details_json=json.dumps({"asset_id":row.id,"asset_type":asset_type}))); db.commit(); db.refresh(row)
    return {"id":row.id,"asset_type":asset_type,"approval_status":row.approval_status,"sha256":row.sha256,"width":row.width,"height":row.height}

@router.post("/admin/image-references/{asset_id}/approve")
def approve_image_reference(asset_id: int, _: None = Depends(admin_only), db: Session = Depends(get_db)):
    row=db.get(BrandImageReference,asset_id)
    if not row: raise HTTPException(404,"Image reference not found")
    row.approval_status="approved"; row.approved_at=datetime.now(timezone.utc); db.add(BrandVerificationAudit(brand_id=row.brand_id,actor="admin",action="image_reference_approved",details_json=json.dumps({"asset_id":row.id}))); db.commit(); return {"id":row.id,"asset_type":row.asset_type,"approval_status":row.approval_status}

@router.get("/providers/google-safe-browsing/status")
def google_safe_browsing_status():
    return google_safe_browsing_configuration()

@router.post("/providers/google-safe-browsing/verify")
def google_safe_browsing_verify(force: bool = False):
    return verify_google_safe_browsing(force=force)

@router.get("/providers/google-safe-browsing/latest")
def google_safe_browsing_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "Google Safe Browsing").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No Google Safe Browsing scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.get("/providers/virustotal/status")
def virustotal_status():
    return virustotal_configuration()

@router.get("/providers/virustotal/latest")
def virustotal_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "VirusTotal").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No VirusTotal scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.post("/providers/virustotal/submit")
def virustotal_submit(payload: dict):
    url = payload.get("url")
    confirmed = payload.get("confirm_public_submission") is True
    if not isinstance(url, str) or not url.strip(): raise HTTPException(400, "url is required")
    return submit_virustotal_url(url, confirmed)

@router.get("/providers/virustotal/analyses/{analysis_id}")
def virustotal_analysis(analysis_id: str):
    if not analysis_id.strip(): raise HTTPException(400, "analysis_id is required")
    return poll_virustotal_analysis(analysis_id)

@router.get("/providers/external/status")
def external_status():
    return external_intelligence_status()

@router.get("/providers/ca-reputation/status")
def ca_reputation_status():
    return ca_reputation_configuration()

@router.get("/providers/external/latest")
def external_latest(db: Session = Depends(get_db)):
    providers = []
    for name in ("AlienVault OTX", "OPSWAT MetaDefender Cloud"):
        row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == name).order_by(ProviderVerdict.checked_at.desc()).first()
        providers.append({"provider": name, "status": row.status if row else "no_scan", "verdict": row.verdict if row else "unknown", "evidence": json.loads(row.evidence_json or "{}") if row else {}, "checked_at": row.checked_at if row else None})
    return {"providers": providers}

@router.get("/providers/urlhaus/status")
def urlhaus_status():
    return urlhaus_connectivity_status()

@router.get("/providers/urlhaus/latest")
def urlhaus_latest(db: Session = Depends(get_db)):
    row = db.query(ProviderVerdict).filter(ProviderVerdict.provider == "URLhaus").order_by(ProviderVerdict.checked_at.desc()).first()
    if not row:
        return {"status": "no_scan", "verdict": "unknown", "message": "No URLhaus scan result is stored yet."}
    return {"provider": row.provider, "status": row.status, "verdict": row.verdict, "evidence": json.loads(row.evidence_json or "{}"), "checked_at": row.checked_at}

@router.post("/scans")
def create_scan(payload: ScanRequest, db: Session = Depends(get_db)):
    try: result = scan(payload.url, db)
    except ValueError as exc: raise HTTPException(400, str(exc))
    registered = db.query(BrandRegistry).filter(BrandRegistry.official_domain == result["domain"].lower().rstrip("."), BrandRegistry.verification_status == "verified").first()
    if registered:
        result.setdefault("domain_intelligence", {}).setdefault("domain", {})["ownership"] = {"status":"verified", "confidence":"high", "brand":registered.brand_name, "official_domain":registered.official_domain, "source":registered.source, "verification_date":registered.verification_date, "message":"Exact domain match to an administrator-verified brand registry record."}
    identity=result.setdefault("domain_intelligence",{}).setdefault("identity",{})
    comparisons=[]; favicon_comparisons=[]
    for candidate in identity.get("logo_assets",[]):
        if candidate.get("status")!="available" or not candidate.get("phash"): continue
        for ref in db.query(BrandLogoAsset).filter(BrandLogoAsset.approval_status=="approved").all():
            brand=db.get(BrandRegistry,ref.brand_id); match=compare(candidate["phash"],ref.phash)
            if match.get("status")=="compared" and (match.get("exact_match") or match.get("similarity_percent",0) >= 78): comparisons.append({**match,"brand":brand.brand_name if brand else "Unknown","brand_id":brand.id if brand else None,"official_domain":brand.official_domain if brand else None,"reference_logo_id":ref.id,"candidate_url":candidate.get("url")})
    for candidate in identity.get("favicon_candidates",[]):
        if candidate.get("status")!="available": continue
        for ref in db.query(BrandImageReference).filter(BrandImageReference.asset_type=="favicon",BrandImageReference.approval_status=="approved").all():
            brand=db.get(BrandRegistry,ref.brand_id); match=compare_fingerprints(candidate,{"status":"available","sha256":ref.sha256,"phash":ref.phash,"dhash":ref.dhash,"ahash":ref.ahash})
            if match.get("status")=="compared" and (match.get("exact_match") or match.get("similarity_percent",0) >= 78): favicon_comparisons.append({**match,"brand":brand.brand_name if brand else "Unknown","brand_id":brand.id if brand else None,"official_domain":brand.official_domain if brand else None,"reference_asset_id":ref.id,"candidate_url":candidate.get("url")})
    identity["logo_comparisons"]=comparisons or {"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No approved reference logo matched or no approved reference exists"}
    identity["favicon_comparisons"]=favicon_comparisons or {"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No approved reference favicon matched or no approved reference exists"}
    identity["findings"]=[]
    for finding_type, matches in (("logo",comparisons),("favicon",favicon_comparisons if isinstance(favicon_comparisons,list) else [])):
        for match in matches:
            finding={"finding_type":f"{finding_type}_reference_match","brand":match.get("brand"),"brand_id":match.get("brand_id"),"reference_asset_id":match.get("reference_asset_id") or match.get("reference_logo_id"),"candidate_url":match.get("candidate_url"),"similarity":match.get("similarity_percent"),"exact_match":match.get("exact_match",False),"confidence":match.get("confidence"),"source":"approved_brand_reference","checked_at":datetime.now(timezone.utc).isoformat(),"risk_contribution":0,"explanation":"Image similarity is supporting identity evidence and is not proof of ownership or fraud."}
            identity["findings"].append(finding)
    result["risk"] = calculate(result.get("phishing",{}), result.get("network",{}), result.get("threat_intelligence",{}), result.get("domain_intelligence",{}), result.get("certificate",{}))
    row = Scan(url=payload.url, normalized_url=result["normalized_url"], domain=result["domain"], risk_score=result["risk"]["score"], risk_level=result["risk"]["level"], result_json=json.dumps(result))
    db.add(row); db.commit(); db.refresh(row)
    intel=result.get("domain_intelligence",{}); db.add(DomainIntelligence(scan_id=row.id,domain=row.domain,rdap_json=json.dumps(intel.get("rdap",{})),infrastructure_json=json.dumps(intel.get("infrastructure",{})),identity_json=json.dumps(intel.get("identity",{}))))
    certificate=result.get("certificate",{}); cert_items=certificate.get("certificates",[])
    for item in cert_items:
        def parse_date(value):
            try: return datetime.fromisoformat(value.replace("Z","+00:00")) if value else None
            except (ValueError,AttributeError): return None
        der=bytes.fromhex(item["der"]) if item.get("der") else None
        db.add(CertificateRecord(scan_id=row.id,fingerprint_sha256=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),subject=item.get("subject"),issuer=item.get("issuer"),serial_number=item.get("serial_number"),not_before=parse_date(item.get("not_before")),not_after=parse_date(item.get("not_after")),der=der,parsed_json=json.dumps({k:v for k,v in item.items() if k != "der"})))
    db.flush()
    for index,item in enumerate(cert_items[:-1]):
        issuer=cert_items[index+1]
        db.add(CertificateChainLink(scan_id=row.id,child_fingerprint=item.get("fingerprint_sha256",""),issuer_fingerprint=issuer.get("fingerprint_sha256"),relation="presented_issuer",position=index,evidence_json=json.dumps({"child_subject":item.get("subject"),"issuer_subject":issuer.get("subject")})))
    validation=certificate.get("validation",{})
    db.add(CertificateValidationResult(scan_id=row.id,status=validation.get("status",certificate.get("status","UNKNOWN")),trust_anchor=(validation.get("trust_anchor") or {}).get("fingerprint_sha256"),errors_json=json.dumps(validation.get("errors",[])),evidence_json=json.dumps(validation),checked_at=datetime.now(timezone.utc)))
    cert_risk=certificate.get("risk",{})
    db.add(CertificateRiskAssessment(scan_id=row.id,score=int(cert_risk.get("score",0) or 0),level=cert_risk.get("level","Informational"),confidence=cert_risk.get("confidence"),validation_status=cert_risk.get("validation_status"),tls_grade=cert_risk.get("tls_grade"),revocation_status=cert_risk.get("revocation_status"),ca_trust_status=cert_risk.get("ca_trust_status"),ct_anomaly_score=int(cert_risk.get("ct_anomaly_score",0) or 0),findings_json=json.dumps(cert_risk.get("findings",[])),evidence_json=json.dumps(cert_risk),checked_at=datetime.now(timezone.utc)))
    ct=certificate.get("ct_intelligence",{})
    for item in ct.get("records",[]):
        db.add(CertificateTransparencyEntry(scan_id=row.id,certificate_id=str(item.get("certificate_id")) if item.get("certificate_id") is not None else None,fingerprint_sha256=item.get("fingerprint_sha256"),issuer=item.get("issuer"),subject=item.get("subject"),san_json=json.dumps(item.get("san_domains",[])),serial_number=item.get("serial_number"),not_before=parse_date(item.get("not_before")),not_after=parse_date(item.get("not_after")),observation_timestamp=parse_date(item.get("observation_timestamp")),ct_log=item.get("ct_log"),source=item.get("source","crt.sh"),status=item.get("status","OBSERVED")))
    for item in ct.get("anomalies",[]):
        db.add(CertificateTransparencyAnomaly(scan_id=row.id,finding_type=item.get("finding_type","unknown"),fingerprint=item.get("fingerprint"),domain=item.get("domain"),issuer=item.get("issuer"),source=item.get("source"),observation_timestamp=parse_date(item.get("observation_timestamp")),confidence=item.get("confidence"),evidence_json=json.dumps(item.get("evidence",{})),explanation=item.get("explanation")))
    for item in certificate.get("revocation",{}).get("certificates",[]):
        aggregate=item.get("aggregate",{}); sources=aggregate.get("sources",{}); ca_trust=item.get("ca_trust",{})
        db.add(CertificateRevocationResult(scan_id=row.id,certificate_fingerprint=item.get("fingerprint_sha256",""),role=item.get("role","unknown"),status=aggregate.get("status","UNKNOWN"),ocsp_status=(sources.get("ocsp") or {}).get("status"),crl_status=(sources.get("crl") or {}).get("status"),distrust_status=ca_trust.get("status"),ca_reputation=ca_trust.get("ca_reputation"),evidence_json=json.dumps(item),checked_at=datetime.now(timezone.utc)))
    candidate_rows=[]
    for asset_type, values in (("logo",identity.get("logo_assets",[])),("favicon",identity.get("favicon_candidates",[]))):
        for item in values:
            candidate_row=WebsiteImageCandidate(scan_id=row.id,asset_type=asset_type,source_url=item.get("url","")[:2048],extraction_method=item.get("source"),status=item.get("status"),format=item.get("detected_format") or item.get("format"),width=item.get("width"),height=item.get("height"),sha256=item.get("sha256"),phash=item.get("phash"),dhash=item.get("dhash"))
            db.add(candidate_row); candidate_rows.append(candidate_row)
    db.flush()
    for finding in identity.get("findings",[]):
        candidate=next((x for x in candidate_rows if x.source_url==finding.get("candidate_url") and x.asset_type==finding.get("finding_type","").split("_",1)[0]),None)
        db.add(ImageComparison(scan_id=row.id,candidate_id=candidate.id if candidate else None,reference_id=finding.get("reference_asset_id"),brand_id=finding.get("brand_id"),asset_type="favicon" if "favicon" in finding.get("finding_type","") else "logo",similarity=finding.get("similarity"),exact_match=str(finding.get("exact_match",False)),confidence=finding.get("confidence"),method="approved reference image comparison",evidence_json=json.dumps(finding),checked_at=datetime.now(timezone.utc)))
    for provider in result.get("threat_intelligence",{}).get("providers",[]): db.add(ProviderVerdict(scan_id=row.id,provider=provider.get("provider","unknown"),status=provider.get("status","unknown"),verdict=provider.get("verdict"),evidence_json=json.dumps(provider)))
    for finding in result.get("threat_intelligence",{}).get("findings",[]):
        source=finding.get("provider") or "unknown"
        existing=db.query(ThreatIndicator).filter(ThreatIndicator.indicator==row.domain, ThreatIndicator.indicator_type=="domain", ThreatIndicator.source==source).first()
        if existing:
            existing.last_seen=row.created_at; existing.category=finding.get("provider"); existing.verification_status=finding.get("state","unverified"); existing.confidence=max(existing.confidence or 0, 1 if finding.get("state")=="confirmed" else .5); existing.source_reference=finding.get("reference")
        else:
            db.add(ThreatIndicator(indicator=row.domain,indicator_type="domain",category=finding.get("provider"),confidence=1 if finding.get("state")=="confirmed" else .5,verification_status=finding.get("state","unverified"),source=source,source_reference=finding.get("reference")))
    for hop in result.get("network",{}).get("http",{}).get("redirects",[]):
        db.add(RedirectHop(scan_id=row.id, sequence=hop.get("sequence", 0), source_url=hop.get("source_url", ""), destination_url=hop.get("destination_url", ""), source_domain=hop.get("source_domain"), destination_domain=hop.get("destination_domain"), status_code=hop.get("status_code"), redirect_type=hop.get("redirect_type"), https=str(hop.get("https")), https_downgrade=str(hop.get("https_downgrade")), destination_ips_json=json.dumps(hop.get("destination_ips", [])), reputation_json=json.dumps(result.get("network",{}).get("redirect_analysis",{}).get("destinations",{}).get(hop.get("destination_domain"), {})), analysis_status=hop.get("analysis_status", "complete")))
    db.commit()
    return {"id": row.id, **result, "created_at": row.created_at}

@router.get("/scans")
def history(limit: int = 20, db: Session = Depends(get_db)):
    return [{"id": x.id, "url": x.url, "domain": x.domain, "risk_score": x.risk_score, "risk_level": x.risk_level, "created_at": x.created_at} for x in db.query(Scan).order_by(Scan.created_at.desc()).limit(min(limit, 100)).all()]

@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row: raise HTTPException(404, "Scan not found")
    return {"id": row.id, **json.loads(row.result_json), "created_at": row.created_at}

@router.get("/scans/{scan_id}/certificate")
def certificate_details(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(Scan,scan_id)
    if not row: raise HTTPException(404,"Scan not found")
    result=json.loads(row.result_json); return {"scan_id":scan_id,"domain":row.domain,"certificate":result.get("certificate",{}),"validation":result.get("certificate",{}).get("validation",{}),"ct_records":result.get("certificate",{}).get("ct_records",[]),"checked_at":result.get("certificate",{}).get("checked_at")}

@router.get("/scans/{scan_id}/certificate/chain")
def certificate_chain_details(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    result=json.loads(db.get(Scan,scan_id).result_json); cert=result.get("certificate",{}); validation=cert.get("validation",{}); return {"scan_id":scan_id,"certificates":[{k:v for k,v in item.items() if k != "der"} for item in cert.get("certificates",[])],"trust_anchor":validation.get("trust_anchor"),"errors":cert.get("errors",[]),"status":validation.get("status",cert.get("status","UNKNOWN")),"validation":validation,"alternative_paths":validation.get("alternative_paths",cert.get("alternative_paths",[]))}

@router.get("/scans/{scan_id}/certificate/validation")
def certificate_validation(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(CertificateValidationResult,db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan_id).order_by(CertificateValidationResult.checked_at.desc()).first().id if db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan_id).first() else -1)
    if not row: raise HTTPException(404,"Certificate validation not found")
    return {"scan_id":scan_id,"status":row.status,"trust_anchor":row.trust_anchor,"errors":json.loads(row.errors_json or "[]"),"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at}

@router.get("/scans/{scan_id}/certificate/revocation")
def certificate_revocation(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan, scan_id): raise HTTPException(404, "Scan not found")
    rows=db.query(CertificateRevocationResult).filter(CertificateRevocationResult.scan_id==scan_id).order_by(CertificateRevocationResult.role,CertificateRevocationResult.id).all()
    statuses=[row.status for row in rows]
    overall="REVOKED" if "REVOKED" in statuses else "UNKNOWN" if not rows or any(item in {"UNKNOWN","UNAVAILABLE","INVALID_RESPONSE"} for item in statuses) else "GOOD"
    return {"scan_id":scan_id,"status":overall,"certificates":[{"fingerprint_sha256":row.certificate_fingerprint,"role":row.role,"status":row.status,"ocsp_status":row.ocsp_status,"crl_status":row.crl_status,"distrust_status":row.distrust_status,"ca_reputation":row.ca_reputation,"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at} for row in rows]}

@router.get("/scans/{scan_id}/certificate/transparency")
def certificate_transparency(scan_id: int, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    result=json.loads(db.get(Scan,scan_id).result_json); ct=result.get("certificate",{}).get("ct_intelligence",{})
    entries=db.query(CertificateTransparencyEntry).filter(CertificateTransparencyEntry.scan_id==scan_id).order_by(CertificateTransparencyEntry.not_before,CertificateTransparencyEntry.observation_timestamp).all()
    anomalies=db.query(CertificateTransparencyAnomaly).filter(CertificateTransparencyAnomaly.scan_id==scan_id).order_by(CertificateTransparencyAnomaly.observation_timestamp).all()
    return {"scan_id":scan_id,"status":ct.get("status","UNAVAILABLE"),"source":ct.get("source","crt.sh"),"query":ct.get("query"),"checked_at":ct.get("checked_at"),"errors":ct.get("errors",[]),"entries":[{"certificate_id":row.certificate_id,"fingerprint_sha256":row.fingerprint_sha256,"issuer":row.issuer,"subject":row.subject,"san_domains":json.loads(row.san_json or "[]"),"serial_number":row.serial_number,"not_before":row.not_before,"not_after":row.not_after,"observation_timestamp":row.observation_timestamp,"ct_log":row.ct_log,"source":row.source,"status":row.status} for row in entries],"anomalies":[{"finding_type":row.finding_type,"fingerprint":row.fingerprint,"domain":row.domain,"issuer":row.issuer,"source":row.source,"observation_timestamp":row.observation_timestamp,"confidence":row.confidence,"evidence":json.loads(row.evidence_json or "{}"),"explanation":row.explanation} for row in anomalies]}

@router.get("/scans/{scan_id}/certificate/risk")
def certificate_risk(scan_id: int, db: Session = Depends(get_db)):
    row=db.query(CertificateRiskAssessment).filter(CertificateRiskAssessment.scan_id==scan_id).order_by(CertificateRiskAssessment.checked_at.desc()).first()
    if not row: raise HTTPException(404,"Certificate risk assessment not found")
    return {"scan_id":scan_id,"score":row.score,"level":row.level,"confidence":row.confidence,"validation_status":row.validation_status,"tls_grade":row.tls_grade,"revocation_status":row.revocation_status,"ca_trust_status":row.ca_trust_status,"ct_anomaly_score":row.ct_anomaly_score,"findings":json.loads(row.findings_json or "[]"),"evidence":json.loads(row.evidence_json or "{}"),"checked_at":row.checked_at}

@router.post("/scans/{scan_id}/certificate/revocation/refresh")
def refresh_certificate_revocation(scan_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not db.get(Scan,scan_id): raise HTTPException(404,"Scan not found")
    active=db.query(CertificateRevocationJob).filter(CertificateRevocationJob.scan_id==scan_id,CertificateRevocationJob.status.in_(["PENDING","RUNNING"])).first()
    if active: return {"job_id":active.id,"status":active.status}
    job=CertificateRevocationJob(scan_id=scan_id,status="PENDING",requested_at=datetime.now(timezone.utc)); db.add(job); db.commit(); db.refresh(job)
    background_tasks.add_task(_refresh_revocation_job,job.id,scan_id)
    return {"job_id":job.id,"status":"PENDING"}

@router.get("/certificate/revocation/jobs/{job_id}")
def certificate_revocation_job(job_id: int, db: Session = Depends(get_db)):
    job=db.get(CertificateRevocationJob,job_id)
    if not job: raise HTTPException(404,"Revocation job not found")
    return {"job_id":job.id,"scan_id":job.scan_id,"status":job.status,"requested_at":job.requested_at,"started_at":job.started_at,"completed_at":job.completed_at,"error":job.error}

@router.get("/domains/{domain}/certificate/history")
def certificate_history(domain: str, db: Session = Depends(get_db)):
    return [{"scan_id":scan.id,"status":validation.status,"checked_at":validation.checked_at} for scan in db.query(Scan).filter(Scan.domain==domain.lower().rstrip(".")).all() for validation in db.query(CertificateValidationResult).filter(CertificateValidationResult.scan_id==scan.id).all()]

@router.get("/scans/{scan_id}/infrastructure-graph")
def infrastructure_graph(scan_id: int, db: Session = Depends(get_db)):
    row=db.get(Scan, scan_id)
    if not row: raise HTTPException(404,"Scan not found")
    result=json.loads(row.result_json); intel=result.get("domain_intelligence",{}); current_ips=set((intel.get("infrastructure") or {}).get("ips",[])); current_ns=set((intel.get("rdap") or {}).get("nameservers",[])); related=[]
    for item in db.query(DomainIntelligence).filter(DomainIntelligence.scan_id != scan_id).order_by(DomainIntelligence.created_at.desc()).limit(100).all():
        try: other=json.loads(item.infrastructure_json or "{}"); other_intel=json.loads(item.rdap_json or "{}"); other_ips=set(other.get("ips",[])); other_ns=set(other_intel.get("nameservers",[]))
        except (ValueError,TypeError): continue
        if current_ips & other_ips: related.append({"domain":item.domain,"relationship":"shared_ip","evidence":f"Shared IP: {', '.join(sorted(current_ips & other_ips))}"})
        elif current_ns & other_ns: related.append({"domain":item.domain,"relationship":"shared_nameserver","evidence":f"Shared nameserver: {', '.join(sorted(current_ns & other_ns))}"})
    return build_graph(row.domain,intel,result.get("threat_intelligence",{}).get("findings",[]),related)

@router.get("/scans/{scan_id}/redirects")
def redirect_chain(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row: raise HTTPException(404, "Scan not found")
    result = json.loads(row.result_json)
    analysis = result.get("network", {}).get("redirect_analysis", {})
    hops = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id).order_by(RedirectHop.sequence).all()
    return {"scan_id": scan_id, "original_url": row.normalized_url, "hops": [json.loads(json.dumps({"sequence":h.sequence,"source_url":h.source_url,"destination_url":h.destination_url,"source_domain":h.source_domain,"destination_domain":h.destination_domain,"status_code":h.status_code,"redirect_type":h.redirect_type,"https":h.https,"https_downgrade":h.https_downgrade,"destination_ips":json.loads(h.destination_ips_json or "[]"),"reputation":json.loads(h.reputation_json or "{}"),"analysis_status":h.analysis_status,"checked_at":h.checked_at}, default=str)) for h in hops], "risk": analysis.get("risk", {}), "comparison": analysis.get("comparison", {}), "destinations": analysis.get("destinations", {})}

@router.get("/scans/{scan_id}/redirects/{sequence}")
def redirect_hop(scan_id: int, sequence: int, db: Session = Depends(get_db)):
    row = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id, RedirectHop.sequence == sequence).first()
    if not row: raise HTTPException(404, "Redirect hop not found")
    return {"scan_id": scan_id, "sequence": row.sequence, "source_url": row.source_url, "destination_url": row.destination_url, "source_domain": row.source_domain, "destination_domain": row.destination_domain, "status_code": row.status_code, "redirect_type": row.redirect_type, "https": row.https, "https_downgrade": row.https_downgrade, "destination_ips": json.loads(row.destination_ips_json or "[]"), "reputation": json.loads(row.reputation_json or "{}"), "analysis_status": row.analysis_status, "checked_at": row.checked_at}

@router.post("/scans/{scan_id}/redirects/{sequence}/retry")
def retry_redirect_hop(scan_id: int, sequence: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    hop = db.query(RedirectHop).filter(RedirectHop.scan_id == scan_id, RedirectHop.sequence == sequence).first()
    if not row or not hop: raise HTTPException(404, "Redirect hop not found")
    result=json.loads(row.result_json); destination=hop.destination_url; domain=hop.destination_domain
    threats=check_threats(destination); intel=collect_domain_intelligence(destination, domain)
    destination_result={"status":"complete", "verdict":"malicious" if any(p.get("verdict") in {"malicious","phishing"} for p in threats.get("providers",[])) else "suspicious" if any(p.get("verdict")=="suspicious" for p in threats.get("providers",[])) else "unknown", "threat_intelligence":threats, "provider_results":_destination_providers(threats,intel), "brand_matches":intel.get("domain",{}).get("brand_matches",[]), "domain_intelligence":intel}
    analysis=result.setdefault("network",{}).setdefault("redirect_analysis",{}); destinations=analysis.setdefault("destinations",{}); destinations[domain]=destination_result
    analysis["risk"]=score_redirect_chain(result.get("normalized_url",row.normalized_url), result.get("network",{}).get("http",{}).get("redirects",[]), destinations)
    hop.reputation_json=json.dumps(destination_result); hop.analysis_status="complete"; row.result_json=json.dumps(result); row.risk_score=result.get("risk",{}).get("score",row.risk_score); db.commit()
    return {"scan_id":scan_id, "sequence":sequence, **destination_result}

@router.post("/reports")
def report(payload: ReportRequest, db: Session = Depends(get_db)):
    row = CommunityReport(**payload.model_dump()); db.add(row); db.commit(); db.refresh(row); return row

@router.get("/reports")
def reports(db: Session = Depends(get_db)):
    return db.query(CommunityReport).order_by(CommunityReport.created_at.desc()).limit(50).all()

@router.post("/message-analysis")
def message_analysis(payload: dict, db: Session = Depends(get_db)):
    text = payload.get("text", "")
    if not isinstance(text, str) or not 1 <= len(text) <= 20000: raise HTTPException(400, "text must contain 1-20000 characters")
    brands=[{"brand_name": row.brand_name, "official_domain": row.official_domain, "verification_status": row.verification_status} for row in db.query(BrandRegistry).all()]
    email_providers=[{"domain": row.domain, "provider_name": row.provider_name, "category": row.category, "disposable": row.disposable, "source": row.source, "list_version": row.list_version} for row in db.query(EmailProviderRegistry).all()]
    result=analyze_message(text, brands=brands, email_providers=email_providers)
    record=MessageAnalysisRecord(input_sha256=hashlib.sha256(text.encode()).hexdigest(), source_type="TEXT", result_json=json.dumps(result)); db.add(record); db.flush()
    intel=result.get("indicator_intelligence", {})
    for indicator_type in ("urls", "emails", "phones"):
        for item in intel.get(indicator_type, []):
            for provider in item.get("provider_results", []) or [{"provider": item.get("provider", "local"), "status": item.get("status", "UNKNOWN"), "verdict": item.get("verdict", "unknown")}]:
                db.add(MessageIndicatorResult(message_analysis_id=record.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), provider=provider.get("provider", "unknown"), status=provider.get("status", "UNKNOWN"), verdict=provider.get("verdict", "unknown"), result_json=json.dumps(provider)))
            if indicator_type in ("emails", "phones"):
                db.add(ContactRiskAssessment(message_analysis_id=record.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), score=int(item.get("risk_score") or 0), classification=item.get("classification", "UNKNOWN"), confidence=item.get("confidence", "low"), evidence_json=json.dumps(item), checked_at=datetime.now(timezone.utc)))
    for finding in intel.get("domain_spoofing", []): db.add(MessageDomainSpoofingFinding(message_analysis_id=record.id, observed_domain=finding.get("observed_domain", ""), official_domain=finding.get("official_domain"), brand=finding.get("brand"), similarity=finding.get("similarity"), edit_distance=finding.get("edit_distance"), technique=finding.get("technique", "unknown"), confidence=finding.get("confidence", "unknown"), verification_status=finding.get("verification_status", "unknown"), evidence_json=json.dumps(finding)))
    db.commit(); result["analysis_id"] = record.id
    return result

@router.post("/message-analysis/email")
async def email_message_analysis(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = file.filename or "uploaded.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are supported")
    raw = await file.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(413, "Email file exceeds the 10 MB limit")
    try:
        result = analyze_email(raw, filename, file.content_type or "")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    dkim_results = verify_dkim_signatures(raw)
    result["dkim_verification"] = dkim_results
    for item in result.get("authentication", []):
        if item.get("mechanism") == "DKIM": item["independent_verification"] = dkim_results
    sender = result.get("sender", {})
    brands=[{"brand_name": item.brand_name, "official_domain": item.official_domain, "verification_status": item.verification_status} for item in db.query(BrandRegistry).all()]
    email_providers=[{"domain": item.domain, "provider_name": item.provider_name, "category": item.category, "disposable": item.disposable, "source": item.source, "list_version": item.list_version} for item in db.query(EmailProviderRegistry).all()]
    result["indicator_intelligence"] = analyze_indicators(result.get("indicators", {}), sender=sender, brands=brands, email_providers=email_providers)
    row = EmailAnalysis(filename=filename, content_type=file.content_type or "", size_bytes=len(raw), message_id=sender.get("message_id"), sender=sender.get("from"), subject=sender.get("subject"), analysis_status=result.get("status", "COMPLETED"), result_json=json.dumps(result))
    db.add(row); db.flush(); db.add(EmailRawMessage(analysis_id=row.id, raw_bytes=raw, sha256=hashlib.sha256(raw).hexdigest()))
    for item in result.get("headers", []): db.add(EmailHeader(analysis_id=row.id, header_name=item["name"], header_value=item["value"], normalized_value=item.get("normalized"), position=item.get("position", 0)))
    for item in result.get("authentication", []): db.add(EmailAuthenticationResult(analysis_id=row.id, mechanism=item["mechanism"], status=item["status"], domain=item.get("domain"), selector=item.get("selector"), source=item.get("source"), evidence_json=json.dumps(item.get("evidence", {})), checked_at=datetime.now(timezone.utc)))
    for item in result.get("anomalies", []): db.add(EmailHeaderAnomaly(analysis_id=row.id, anomaly_type=item["type"], severity=item["severity"], evidence=item["evidence"], created_at=datetime.now(timezone.utc)))
    intel=result.get("indicator_intelligence", {})
    for indicator_type in ("urls", "emails", "phones"):
        for item in intel.get(indicator_type, []):
            for provider in item.get("provider_results", []) or [{"provider": item.get("provider", "local"), "status": item.get("status", "UNKNOWN"), "verdict": item.get("verdict", "unknown")}]:
                db.add(MessageIndicatorResult(email_analysis_id=row.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), provider=provider.get("provider", "unknown"), status=provider.get("status", "UNKNOWN"), verdict=provider.get("verdict", "unknown"), result_json=json.dumps(provider)))
            if indicator_type in ("emails", "phones"):
                db.add(ContactRiskAssessment(email_analysis_id=row.id, indicator_type=indicator_type[:-1], indicator=item.get("indicator", ""), score=int(item.get("risk_score") or 0), classification=item.get("classification", "UNKNOWN"), confidence=item.get("confidence", "low"), evidence_json=json.dumps(item), checked_at=datetime.now(timezone.utc)))
    for finding in intel.get("domain_spoofing", []): db.add(MessageDomainSpoofingFinding(email_analysis_id=row.id, observed_domain=finding.get("observed_domain", ""), official_domain=finding.get("official_domain"), brand=finding.get("brand"), similarity=finding.get("similarity"), edit_distance=finding.get("edit_distance"), technique=finding.get("technique", "unknown"), confidence=finding.get("confidence", "unknown"), verification_status=finding.get("verification_status", "unknown"), evidence_json=json.dumps(finding)))
    db.add(EmailVerificationRun(analysis_id=row.id, verification_type="DKIM", result_json=json.dumps({"signatures": dkim_results}), source="independent cryptographic verification"))
    db.commit(); result["analysis_id"] = row.id
    return result

@router.post("/message-analysis/email/{analysis_id}/smtp-context")
def ingest_smtp_context(analysis_id: int, payload: dict, x_smtp_context_token: str | None = Header(default=None), db: Session = Depends(get_db)):
    if not settings.smtp_context_shared_secret or not x_smtp_context_token or not secrets.compare_digest(x_smtp_context_token, settings.smtp_context_shared_secret):
        raise HTTPException(403, "Authenticated SMTP context is required")
    row = db.get(EmailAnalysis, analysis_id)
    raw_row = db.query(EmailRawMessage).filter(EmailRawMessage.analysis_id == analysis_id).first()
    if not row or not raw_row: raise HTTPException(404, "Email analysis not found")
    required = [payload.get(key) for key in ("smtp_client_ip", "envelope_mail_from", "helo_hostname", "receiving_server", "message_id", "trusted_source", "received_at")]
    if not all(isinstance(value, str) and value.strip() for value in required): raise HTTPException(400, "All trusted SMTP context fields are required")
    result = json.loads(row.result_json); expected_message_id = result.get("sender", {}).get("message_id", "")
    if payload["message_id"] != expected_message_id: raise HTTPException(400, "SMTP context does not match the uploaded Message-ID")
    try: received_at = datetime.fromisoformat(payload["received_at"].replace("Z", "+00:00"))
    except ValueError: raise HTTPException(400, "received_at must be an ISO timestamp")
    if received_at.tzinfo is None: received_at = received_at.replace(tzinfo=timezone.utc)
    age_seconds = (datetime.now(timezone.utc) - received_at).total_seconds()
    if age_seconds < -300 or age_seconds > settings.smtp_context_max_age_seconds: raise HTTPException(400, "SMTP context timestamp is outside the accepted age window")
    context = {**payload, "received_at": received_at.isoformat()}
    spf_result = evaluate_spf_context(context, result.get("sender", {}).get("from_domain"), [])
    dmarc_domain = result.get("sender", {}).get("from_domain")
    dmarc_records = []
    if dmarc_domain:
        from backend.app.engines.email_analysis import _dns_txt
        _, dmarc_records, _ = _dns_txt(f"_dmarc.{dmarc_domain}")
    dkim_results = result.get("dkim_verification", [])
    dmarc_result = evaluate_dmarc_alignment(dmarc_domain, spf_result, dkim_results, dmarc_records)
    verification = {"smtp_context": context, "spf": spf_result, "dkim": dkim_results, "dmarc": dmarc_result, "checked_at": datetime.now(timezone.utc).isoformat()}
    result["trusted_authentication"] = verification; row.result_json = json.dumps(result)
    db.add(EmailSmtpContext(analysis_id=analysis_id, smtp_client_ip=context["smtp_client_ip"], envelope_mail_from=context["envelope_mail_from"], helo_hostname=context["helo_hostname"], receiving_server=context["receiving_server"], message_id=context["message_id"], trusted_source=context["trusted_source"], received_at=received_at))
    for mechanism, value in (("SPF", spf_result), ("DKIM", {"signatures": dkim_results}), ("DMARC", dmarc_result)):
        db.add(EmailVerificationRun(analysis_id=analysis_id, verification_type=mechanism, result_json=json.dumps(value), source=context["trusted_source"]))
    db.commit(); result["analysis_id"] = analysis_id
    return result

@router.get("/message-analysis/email/{analysis_id}")
def email_message_analysis_result(analysis_id: int, db: Session = Depends(get_db)):
    row = db.get(EmailAnalysis, analysis_id)
    if not row: raise HTTPException(404, "Email analysis not found")
    result = json.loads(row.result_json); result["analysis_id"] = row.id; result["created_at"] = row.created_at
    return result

@router.get("/ml/status")
def model_status():
    return ml_status()

@router.get("/llm/status")
def llm_status():
    return configuration_status()

@router.post("/llm/verify")
def llm_verify():
    return verify_llm_connection()

@router.get("/correlation")
def correlation(db: Session = Depends(get_db)):
    return correlate(db.query(Scan).all(), db.query(CommunityReport).all())

@router.get("/reports/{report_id}/commitment")
def report_commitment(report_id: int, db: Session = Depends(get_db)):
    row=db.get(CommunityReport, report_id)
    if not row: raise HTTPException(404, "Report not found")
    return commitment({"id":row.id,"url":row.url,"reason":row.reason,"details":row.details,"status":row.status,"created_at":row.created_at})

@router.post("/reports/{report_id}/moderate")
def moderate_report(report_id: int, status: str, db: Session = Depends(get_db), _: None = Depends(admin_only)):
    if status not in {"pending","verified","rejected"}: raise HTTPException(400, "Invalid report status")
    row=db.get(CommunityReport, report_id)
    if not row: raise HTTPException(404, "Report not found")
    row.status=status; db.commit(); return {"id":row.id,"status":row.status}
