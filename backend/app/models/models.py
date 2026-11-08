from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text, Float, ForeignKey, UniqueConstraint, LargeBinary
from backend.app.db.session import Base

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(30), default="complete")
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="Low")
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class CommunityReport(Base):
    __tablename__ = "community_reports"
    id = Column(Integer, primary_key=True)
    url = Column(String(2048), nullable=False)
    reason = Column(String(255), nullable=False)
    details = Column(Text, default="")
    status = Column(String(20), default="pending")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id=Column(Integer,primary_key=True); indicator=Column(String(2048),nullable=False,index=True); indicator_type=Column(String(40),nullable=False); category=Column(String(80)); confidence=Column(Float,default=0); verification_status=Column(String(30),default="unverified"); source=Column(String(100)); source_reference=Column(String(2048)); first_seen=Column(DateTime,default=lambda:datetime.now(timezone.utc)); last_seen=Column(DateTime,default=lambda:datetime.now(timezone.utc)); expires_at=Column(DateTime)
    __table_args__=(UniqueConstraint("indicator","indicator_type","source",name="uq_threat_indicator_source"),)

class ProviderVerdict(Base):
    __tablename__="provider_verdicts"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); provider=Column(String(100),nullable=False); status=Column(String(30),nullable=False); verdict=Column(String(40)); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class DomainIntelligence(Base):
    __tablename__="domain_intelligence"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); domain=Column(String(255),index=True); rdap_json=Column(Text,default="{}"); infrastructure_json=Column(Text,default="{}"); identity_json=Column(Text,default="{}"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class RedirectHop(Base):
    __tablename__ = "redirect_hops"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); sequence=Column(Integer,nullable=False); source_url=Column(String(2048),nullable=False); destination_url=Column(String(2048),nullable=False); source_domain=Column(String(255)); destination_domain=Column(String(255),index=True); status_code=Column(Integer); redirect_type=Column(String(30)); https=Column(String(10)); https_downgrade=Column(String(10)); destination_ips_json=Column(Text,default="[]"); reputation_json=Column(Text,default="{}"); analysis_status=Column(String(30),default="complete"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BrandRegistry(Base):
    __tablename__ = "brand_registry"
    id=Column(Integer,primary_key=True); brand_name=Column(String(120),nullable=False); official_domain=Column(String(255),nullable=False,index=True); official_website=Column(String(2048)); logo_url=Column(String(2048)); verification_status=Column(String(30),default="unknown"); source=Column(String(255)); source_reliability=Column(String(30)); verification_date=Column(DateTime); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BrandVerificationEvidence(Base):
    __tablename__ = "brand_verification_evidence"
    id=Column(Integer,primary_key=True); brand_id=Column(Integer,ForeignKey("brand_registry.id"),index=True); evidence_type=Column(String(80),nullable=False); evidence_value=Column(Text,nullable=False); source=Column(String(255)); status=Column(String(30),default="unverified"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BrandVerificationChallenge(Base):
    __tablename__ = "brand_verification_challenges"
    id=Column(Integer,primary_key=True); brand_id=Column(Integer,ForeignKey("brand_registry.id"),index=True); domain=Column(String(255),nullable=False,index=True); method=Column(String(30),nullable=False); token_hash=Column(String(64),nullable=False); challenge_path=Column(String(255)); status=Column(String(30),default="pending"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); expires_at=Column(DateTime,nullable=False); verified_at=Column(DateTime)

class BrandVerificationAudit(Base):
    __tablename__ = "brand_verification_audit"
    id=Column(Integer,primary_key=True); brand_id=Column(Integer,ForeignKey("brand_registry.id"),index=True); actor=Column(String(120),nullable=False); action=Column(String(80),nullable=False); details_json=Column(Text,default="{}"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BrandLogoAsset(Base):
    __tablename__ = "brand_logo_assets"
    id=Column(Integer,primary_key=True); brand_id=Column(Integer,ForeignKey("brand_registry.id"),index=True); original_source=Column(String(2048)); content_type=Column(String(120),nullable=False); width=Column(Integer); height=Column(Integer); phash=Column(String(128),nullable=False); image_bytes=Column(LargeBinary,nullable=False); approval_status=Column(String(30),default="pending",index=True); source=Column(String(255)); uploaded_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); approved_at=Column(DateTime)

class BrandImageReference(Base):
    __tablename__ = "brand_image_reference_assets"
    id=Column(Integer,primary_key=True); brand_id=Column(Integer,ForeignKey("brand_registry.id"),index=True); asset_type=Column(String(20),nullable=False); original_source=Column(String(2048)); content_type=Column(String(120),nullable=False); width=Column(Integer); height=Column(Integer); sha256=Column(String(64),nullable=False); phash=Column(Text,nullable=False); dhash=Column(Text); ahash=Column(Text); image_bytes=Column(LargeBinary,nullable=False); approval_status=Column(String(30),default="pending",index=True); source=Column(String(255)); uploaded_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); approved_at=Column(DateTime)

class WebsiteImageCandidate(Base):
    __tablename__ = "website_image_candidates"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); asset_type=Column(String(20),nullable=False); source_url=Column(String(2048),nullable=False); extraction_method=Column(String(80)); status=Column(String(30)); format=Column(String(20)); width=Column(Integer); height=Column(Integer); sha256=Column(String(64)); phash=Column(Text); dhash=Column(Text); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class ImageComparison(Base):
    __tablename__ = "image_comparisons"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); candidate_id=Column(Integer,ForeignKey("website_image_candidates.id"),index=True); reference_id=Column(Integer,index=True); brand_id=Column(Integer,index=True); asset_type=Column(String(20),nullable=False); similarity=Column(Float); exact_match=Column(String(10)); confidence=Column(String(20)); method=Column(String(255)); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateRecord(Base):
    __tablename__ = "certificate_records"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); fingerprint_sha256=Column(String(64),index=True,nullable=False); role=Column(String(30),nullable=False); subject=Column(Text); issuer=Column(Text); serial_number=Column(String(255)); not_before=Column(DateTime); not_after=Column(DateTime); der=Column(LargeBinary); parsed_json=Column(Text,default="{}"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateChainLink(Base):
    __tablename__ = "certificate_chain_links"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); child_fingerprint=Column(String(64),nullable=False); issuer_fingerprint=Column(String(64)); relation=Column(String(40),nullable=False); position=Column(Integer); evidence_json=Column(Text,default="{}"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateValidationResult(Base):
    __tablename__ = "certificate_validation_results"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); status=Column(String(30),nullable=False); trust_anchor=Column(String(64)); errors_json=Column(Text,default="[]"); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateRevocationResult(Base):
    __tablename__ = "certificate_revocation_results"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); certificate_fingerprint=Column(String(64),index=True,nullable=False); role=Column(String(30),nullable=False); status=Column(String(30),nullable=False); ocsp_status=Column(String(30)); crl_status=Column(String(30)); distrust_status=Column(String(40)); ca_reputation=Column(String(50)); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateRevocationCache(Base):
    __tablename__ = "certificate_revocation_cache"
    id=Column(Integer,primary_key=True); certificate_fingerprint=Column(String(64),index=True,nullable=False); issuer_fingerprint=Column(String(64),index=True); result_json=Column(Text,nullable=False); checked_at=Column(DateTime,nullable=False); expires_at=Column(DateTime,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); __table_args__=(UniqueConstraint("certificate_fingerprint","issuer_fingerprint",name="uq_certificate_revocation_cache_pair"),)

class CAReputationRecord(Base):
    __tablename__ = "ca_reputation_records"
    id=Column(Integer,primary_key=True); certificate_fingerprint=Column(String(64),index=True,nullable=False); status=Column(String(40),nullable=False); source=Column(String(2048),nullable=False); effective_date=Column(DateTime); details_json=Column(Text,default="{}"); checked_at=Column(DateTime,nullable=False); expires_at=Column(DateTime,nullable=False); __table_args__=(UniqueConstraint("certificate_fingerprint","source",name="uq_ca_reputation_source"),)

class CertificateRevocationJob(Base):
    __tablename__ = "certificate_revocation_jobs"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True,nullable=False); status=Column(String(30),nullable=False,default="PENDING"); requested_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); started_at=Column(DateTime); completed_at=Column(DateTime); error=Column(Text)

class CertificateTransparencyEntry(Base):
    __tablename__ = "certificate_transparency_entries"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); certificate_id=Column(String(120)); fingerprint_sha256=Column(String(128),index=True); issuer=Column(Text); subject=Column(Text); san_json=Column(Text,default="[]"); serial_number=Column(String(255)); not_before=Column(DateTime); not_after=Column(DateTime); observation_timestamp=Column(DateTime); ct_log=Column(String(255)); source=Column(String(255),nullable=False); status=Column(String(30)); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateTransparencyAnomaly(Base):
    __tablename__ = "certificate_transparency_anomalies"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True); finding_type=Column(String(80),nullable=False); fingerprint=Column(String(128)); domain=Column(String(255)); issuer=Column(Text); source=Column(String(255)); observation_timestamp=Column(DateTime); confidence=Column(String(30)); evidence_json=Column(Text,default="{}"); explanation=Column(Text); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class CertificateRiskAssessment(Base):
    __tablename__ = "certificate_risk_assessments"
    id=Column(Integer,primary_key=True); scan_id=Column(Integer,ForeignKey("scans.id"),index=True,nullable=False); score=Column(Integer,nullable=False); level=Column(String(30),nullable=False); confidence=Column(String(30)); validation_status=Column(String(30)); tls_grade=Column(String(10)); revocation_status=Column(String(30)); ca_trust_status=Column(String(40)); ct_anomaly_score=Column(Integer,default=0); findings_json=Column(Text,default="[]"); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
