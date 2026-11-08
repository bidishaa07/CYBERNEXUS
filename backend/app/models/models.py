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

class EmailAnalysis(Base):
    __tablename__ = "email_analyses"
    id=Column(Integer,primary_key=True); filename=Column(String(255)); content_type=Column(String(120)); size_bytes=Column(Integer,nullable=False); message_id=Column(String(512)); sender=Column(String(512)); subject=Column(Text); analysis_status=Column(String(30),default="COMPLETED"); result_json=Column(Text,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailHeader(Base):
    __tablename__ = "email_headers"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True,nullable=False); header_name=Column(String(120),nullable=False); header_value=Column(Text,nullable=False); normalized_value=Column(Text); position=Column(Integer,default=0)

class EmailAuthenticationResult(Base):
    __tablename__ = "email_authentication_results"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True,nullable=False); mechanism=Column(String(20),nullable=False); status=Column(String(30),nullable=False); domain=Column(String(255)); selector=Column(String(255)); source=Column(String(120)); evidence_json=Column(Text,default="{}"); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailHeaderAnomaly(Base):
    __tablename__ = "email_header_anomalies"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True,nullable=False); anomaly_type=Column(String(80),nullable=False); severity=Column(String(20),nullable=False); evidence=Column(Text,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailRawMessage(Base):
    __tablename__ = "email_raw_messages"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),unique=True,index=True,nullable=False); raw_bytes=Column(LargeBinary,nullable=False); sha256=Column(String(64),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailSmtpContext(Base):
    __tablename__ = "email_smtp_contexts"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True,nullable=False); smtp_client_ip=Column(String(64),nullable=False); envelope_mail_from=Column(String(512),nullable=False); helo_hostname=Column(String(255),nullable=False); receiving_server=Column(String(255),nullable=False); message_id=Column(String(512),nullable=False); trusted_source=Column(String(255),nullable=False); received_at=Column(DateTime,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailVerificationRun(Base):
    __tablename__ = "email_verification_runs"
    id=Column(Integer,primary_key=True); analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True,nullable=False); verification_type=Column(String(30),nullable=False); result_json=Column(Text,nullable=False); source=Column(String(255),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageAnalysisRecord(Base):
    __tablename__ = "message_analysis_records"
    id=Column(Integer,primary_key=True); input_sha256=Column(String(64),index=True,nullable=False); source_type=Column(String(30),nullable=False,default="TEXT"); result_json=Column(Text,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageIndicatorResult(Base):
    __tablename__ = "message_indicator_results"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True); indicator_type=Column(String(30),nullable=False); indicator=Column(String(2048),nullable=False); provider=Column(String(120),nullable=False); status=Column(String(30),nullable=False); verdict=Column(String(30),nullable=False); result_json=Column(Text,nullable=False); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageDomainSpoofingFinding(Base):
    __tablename__ = "message_domain_spoofing_findings"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True); observed_domain=Column(String(255),nullable=False); official_domain=Column(String(255)); brand=Column(String(120)); similarity=Column(Float); edit_distance=Column(Integer); technique=Column(String(120)); confidence=Column(String(30)); verification_status=Column(String(30)); evidence_json=Column(Text,nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class EmailProviderRegistry(Base):
    __tablename__ = "email_provider_registry"
    id=Column(Integer,primary_key=True); domain=Column(String(255),unique=True,index=True,nullable=False); provider_name=Column(String(120),nullable=False); category=Column(String(40),nullable=False); disposable=Column(String(10),default="false"); source=Column(String(255),nullable=False); list_version=Column(String(80)); updated_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class ContactRiskAssessment(Base):
    __tablename__ = "contact_risk_assessments"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True); indicator_type=Column(String(30),nullable=False); indicator=Column(String(2048),nullable=False); score=Column(Integer,nullable=False); classification=Column(String(30),nullable=False); confidence=Column(String(30),nullable=False); evidence_json=Column(Text,nullable=False); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class IntelligenceVerification(Base):
    __tablename__ = "intelligence_verifications"
    id=Column(Integer,primary_key=True); indicator_type=Column(String(30),nullable=False,index=True); indicator=Column(String(2048),nullable=False,index=True); provider=Column(String(120),nullable=False); status=Column(String(30),nullable=False); result_json=Column(Text,nullable=False); checked_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BackgroundTaskRun(Base):
    __tablename__ = "background_task_runs"
    id=Column(Integer,primary_key=True); task_id=Column(String(160),unique=True,index=True,nullable=False); task_name=Column(String(160),nullable=False); status=Column(String(30),nullable=False); result_json=Column(Text); error=Column(String(255)); started_at=Column(DateTime); completed_at=Column(DateTime); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageAnalysisMetadata(Base):
    __tablename__ = "message_analysis_metadata"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),unique=True,index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),unique=True,index=True); user_id=Column(String(160),nullable=False,index=True,default="anonymous"); input_type=Column(String(30),nullable=False); sender=Column(String(512)); subject=Column(Text); risk_score=Column(Integer); classification=Column(String(120)); ml_prediction=Column(Integer); ml_confidence=Column(Float); llm_status=Column(String(40)); model_version=Column(String(160)); analysis_status=Column(String(30),nullable=False,default="COMPLETED"); duplicate_of_id=Column(Integer); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class MessageContent(Base):
    __tablename__ = "message_contents"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),unique=True,index=True); content_bytes=Column(LargeBinary,nullable=False); sha256=Column(String(64),nullable=False,index=True); content_type=Column(String(80),nullable=False); protected=Column(String(10),nullable=False,default="true"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageAnalysisEvent(Base):
    __tablename__ = "message_analysis_events"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),index=True); user_id=Column(String(160),nullable=False); event_type=Column(String(60),nullable=False); details_json=Column(Text,nullable=False,default="{}"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class AppUser(Base):
    __tablename__ = "app_users"
    id=Column(Integer,primary_key=True); external_subject=Column(String(512),unique=True,index=True,nullable=False); email=Column(String(512),index=True); display_name=Column(String(255)); role=Column(String(40),nullable=False,default="user"); account_status=Column(String(30),nullable=False,default="active"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); last_login_at=Column(DateTime)

class LegacyIdentityLink(Base):
    __tablename__ = "legacy_identity_links"
    id=Column(Integer,primary_key=True); legacy_user_id=Column(String(160),unique=True,index=True,nullable=False); external_subject=Column(String(512),index=True,nullable=False); linked_by=Column(String(512),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageReview(Base):
    __tablename__ = "message_reviews"
    id=Column(Integer,primary_key=True); message_analysis_id=Column(Integer,ForeignKey("message_analysis_records.id"),unique=True,index=True); email_analysis_id=Column(Integer,ForeignKey("email_analyses.id"),unique=True,index=True); status=Column(String(30),nullable=False,default="PENDING_REVIEW"); assigned_reviewer=Column(String(512)); decision_reason=Column(Text); created_by=Column(String(512),nullable=False); updated_by=Column(String(512),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); updated_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageReviewAudit(Base):
    __tablename__ = "message_review_audits"
    id=Column(Integer,primary_key=True); review_id=Column(Integer,ForeignKey("message_reviews.id"),index=True,nullable=False); reviewer_id=Column(String(512),nullable=False); action=Column(String(60),nullable=False); previous_status=Column(String(30)); new_status=Column(String(30)); reason=Column(Text); note=Column(Text); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MessageReviewFeedback(Base):
    __tablename__ = "message_review_feedback"
    id=Column(Integer,primary_key=True); review_id=Column(Integer,ForeignKey("message_reviews.id"),index=True,nullable=False); reviewer_id=Column(String(512),nullable=False); label=Column(String(40),nullable=False); certainty=Column(String(30)); evidence=Column(Text); approval_status=Column(String(30),nullable=False,default="PENDING_VALIDATION"); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class MLDatasetVersion(Base):
    __tablename__ = "ml_dataset_versions"
    id=Column(Integer,primary_key=True); dataset_id=Column(String(160),index=True,nullable=False); version=Column(String(80),nullable=False); source=Column(Text,nullable=False); checksum=Column(String(64),nullable=False); record_count=Column(Integer,nullable=False); class_distribution_json=Column(Text,nullable=False,default="{}"); quality_json=Column(Text,nullable=False,default="{}"); preprocessing_version=Column(String(120),nullable=False); validation_status=Column(String(30),nullable=False,default="PENDING"); approval_status=Column(String(30),nullable=False,default="PENDING"); created_by=Column(String(512),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); __table_args__=(UniqueConstraint("dataset_id","version",name="uq_ml_dataset_version"),)

class MLModelVersion(Base):
    __tablename__ = "ml_model_versions"
    id=Column(Integer,primary_key=True); model_id=Column(String(160),index=True,nullable=False); version=Column(String(80),nullable=False); name=Column(String(255),nullable=False); algorithm=Column(String(120),nullable=False); dataset_version_id=Column(Integer,ForeignKey("ml_dataset_versions.id"),index=True); artifact_location=Column(Text,nullable=False); artifact_checksum=Column(String(64),nullable=False); feature_config_json=Column(Text,nullable=False,default="{}"); hyperparameters_json=Column(Text,nullable=False,default="{}"); metrics_json=Column(Text,nullable=False,default="{}"); status=Column(String(30),nullable=False,default="CANDIDATE"); approval_by=Column(String(512)); approved_at=Column(DateTime); created_by=Column(String(512),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); __table_args__=(UniqueConstraint("model_id","version",name="uq_ml_model_version"),)

class MLDeploymentHistory(Base):
    __tablename__ = "ml_deployment_history"
    id=Column(Integer,primary_key=True); model_version_id=Column(Integer,ForeignKey("ml_model_versions.id"),index=True,nullable=False); previous_model_version_id=Column(Integer); action=Column(String(30),nullable=False); actor=Column(String(512),nullable=False); artifact_checksum=Column(String(64),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc)); reason=Column(Text)

class MLTrainingRun(Base):
    __tablename__ = "ml_training_runs"
    id=Column(Integer,primary_key=True); dataset_version_id=Column(Integer,ForeignKey("ml_dataset_versions.id"),index=True,nullable=False); model_version_id=Column(Integer,ForeignKey("ml_model_versions.id"),index=True); status=Column(String(30),nullable=False,default="PENDING"); metrics_json=Column(Text,default="{}"); error=Column(Text); started_at=Column(DateTime); completed_at=Column(DateTime); created_by=Column(String(512),nullable=False); created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
