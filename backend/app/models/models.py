from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text, Float, ForeignKey, UniqueConstraint, LargeBinary, event
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

class SecurityAssessment(Base):
    __tablename__ = "security_assessments"
    id=Column(Integer,primary_key=True)
    scan_id=Column(Integer,ForeignKey("scans.id"),index=True)
    user_id=Column(String(160),nullable=False,index=True,default="anonymous")
    target_url=Column(String(2048),nullable=False)
    hostname=Column(String(255),nullable=False,index=True)
    status=Column(String(30),nullable=False,default="COMPLETED",index=True)
    finding_count=Column(Integer,nullable=False,default=0)
    pass_count=Column(Integer,nullable=False,default=0)
    fail_count=Column(Integer,nullable=False,default=0)
    warning_count=Column(Integer,nullable=False,default=0)
    unknown_count=Column(Integer,nullable=False,default=0)
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc),index=True)
    completed_at=Column(DateTime)
    assessment_mode=Column(String(20),nullable=False,default="PASSIVE")
    authorization_id=Column(Integer,index=True)
    stopped_reason=Column(String(255))

class SecurityAuthorization(Base):
    __tablename__ = "security_authorizations"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True)
    target_hostname=Column(String(255),nullable=False,index=True)
    authorized_organization=Column(String(255),nullable=False)
    requester_user_id=Column(String(160),nullable=False,index=True)
    authorization_confirmed=Column(Integer,nullable=False,default=0)
    permitted_scope_json=Column(Text,default="[]")
    allowed_categories_json=Column(Text,default="[]")
    start_time=Column(DateTime,nullable=False)
    expires_at=Column(DateTime,nullable=False,index=True)
    approval_status=Column(String(20),nullable=False,default="PENDING",index=True)
    supporting_reference=Column(String(2048))
    approved_by=Column(String(160))
    approved_at=Column(DateTime)
    revoked_at=Column(DateTime)
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc),index=True)
    updated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class SecurityAuthorizationEvent(Base):
    __tablename__ = "security_authorization_events"
    id=Column(Integer,primary_key=True)
    authorization_id=Column(Integer,ForeignKey("security_authorizations.id"),index=True,nullable=False)
    actor=Column(String(160),nullable=False)
    action=Column(String(40),nullable=False)
    previous_status=Column(String(20))
    new_status=Column(String(20))
    note=Column(Text,default="")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc),index=True)

class SecurityFinding(Base):
    __tablename__ = "security_findings"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    target_url=Column(String(2048),nullable=False)
    hostname=Column(String(255),nullable=False,index=True)
    category=Column(String(50),nullable=False,index=True)
    check_identifier=Column(String(120),nullable=False)
    title=Column(String(255),nullable=False)
    description=Column(Text,default="")
    severity=Column(String(20),nullable=False,default="INFO",index=True)
    confidence=Column(String(20),nullable=False,default="UNKNOWN")
    status=Column(String(30),nullable=False,default="UNKNOWN",index=True)
    observed_value=Column(Text)
    expected_value=Column(Text)
    security_impact=Column(Text,default="")
    remediation=Column(Text,default="")
    evidence_json=Column(Text,default="{}")
    verification_limitations=Column(Text,default="")
    remediation_status=Column(String(30),nullable=False,default="OPEN")
    first_detected=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_detected=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("assessment_id","check_identifier",name="uq_security_finding_check"),)

class SecurityCheckResult(Base):
    __tablename__ = "security_check_results"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    category=Column(String(50),nullable=False,index=True)
    check_identifier=Column(String(120),nullable=False)
    status=Column(String(30),nullable=False)
    result_json=Column(Text,default="{}")
    checked_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("assessment_id","check_identifier",name="uq_security_check_result"),)

class SecurityEvidence(Base):
    __tablename__ = "security_evidence"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    finding_id=Column(Integer,ForeignKey("security_findings.id"),index=True)
    source=Column(String(120),nullable=False)
    evidence_type=Column(String(80),nullable=False)
    details_json=Column(Text,default="{}")
    observed_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class RemediationRecord(Base):
    __tablename__ = "security_remediation_records"
    __table_args__ = (UniqueConstraint("finding_id", name="ux_security_remediation_records_finding_id"),)
    id=Column(Integer,primary_key=True)
    finding_id=Column(Integer,ForeignKey("security_findings.id"),index=True,nullable=False)
    status=Column(String(30),nullable=False,default="OPEN")
    note=Column(Text,default="")
    updated_by=Column(String(160),nullable=False,default="system")
    updated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    assigned_to=Column(String(160))
    proposed_fix=Column(Text,default="")
    applied_fix=Column(Text,default="")
    verification_status=Column(String(30),nullable=False,default="NOT_REQUESTED")
    verification_note=Column(Text,default="")
    verified_by=Column(String(160))
    verified_at=Column(DateTime)

class FindingRemediationEvent(Base):
    __tablename__ = "security_finding_remediation_events"
    id=Column(Integer,primary_key=True)
    finding_id=Column(Integer,ForeignKey("security_findings.id"),index=True,nullable=False)
    actor=Column(String(160),nullable=False)
    action=Column(String(50),nullable=False)
    previous_status=Column(String(30))
    new_status=Column(String(30))
    note=Column(Text,default="")
    verification_result=Column(String(30),default="NOT_REQUESTED")
    details_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc),index=True)

class AssessmentAuthorization(Base):
    __tablename__ = "security_assessment_authorizations"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    user_id=Column(String(160),nullable=False,index=True)
    access_level=Column(String(30),nullable=False,default="VIEW")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("assessment_id","user_id",name="uq_security_assessment_authorization"),)

class AssessmentEvent(Base):
    __tablename__ = "security_assessment_events"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    actor=Column(String(160),nullable=False)
    event_type=Column(String(60),nullable=False)
    details_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class SecurityAssessmentReport(Base):
    __tablename__ = "security_assessment_reports"
    id=Column(Integer,primary_key=True)
    assessment_id=Column(Integer,ForeignKey("security_assessments.id"),index=True,nullable=False)
    generated_by=Column(String(160),nullable=False,index=True)
    report_version=Column(String(30),nullable=False,default="1.0")
    format=Column(String(10),nullable=False)
    status=Column(String(20),nullable=False,default="COMPLETED")
    finding_count=Column(Integer,nullable=False,default=0)
    error=Column(Text,default="")
    generated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc),index=True)

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

class IndicatorObservation(Base):
    __tablename__ = "indicator_observations"
    id=Column(Integer,primary_key=True)
    indicator_id=Column(Integer,ForeignKey("threat_indicators.id"),index=True,nullable=False)
    source_analysis_type=Column(String(40),nullable=False)
    source_analysis_id=Column(String(160),nullable=False,index=True)
    normalized_value=Column(String(2048),nullable=False,index=True)
    original_observed_value=Column(Text,nullable=False)
    source_provider=Column(String(120))
    verification_status=Column(String(30),default="unknown")
    confidence=Column(Float)
    metadata_json=Column(Text,default="{}")
    first_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    observation_count=Column(Integer,default=1)
    __table_args__=(UniqueConstraint("indicator_id","source_analysis_type","source_analysis_id","normalized_value",name="uq_indicator_observation_source"),)

class IndicatorRelationship(Base):
    __tablename__ = "indicator_relationships"
    id=Column(Integer,primary_key=True)
    source_indicator_id=Column(Integer,ForeignKey("threat_indicators.id"),index=True,nullable=False)
    target_indicator_id=Column(Integer,ForeignKey("threat_indicators.id"),index=True,nullable=False)
    relationship_type=Column(String(80),nullable=False)
    status=Column(String(30),default="observed")
    confidence=Column(Float)
    first_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    originating_analysis_type=Column(String(40))
    originating_analysis_id=Column(String(160),index=True)
    __table_args__=(UniqueConstraint("source_indicator_id","target_indicator_id","relationship_type",name="uq_indicator_relationship"),)

class CorrelationEvidence(Base):
    __tablename__ = "correlation_evidence"
    id=Column(Integer,primary_key=True)
    relationship_id=Column(Integer,ForeignKey("indicator_relationships.id"),index=True)
    result_id=Column(Integer,ForeignKey("correlation_results.id"),index=True)
    evidence_type=Column(String(80),nullable=False)
    source=Column(String(120),nullable=False)
    details_json=Column(Text,default="{}")
    confidence=Column(Float)
    observed_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class CorrelationResult(Base):
    __tablename__ = "correlation_results"
    id=Column(Integer,primary_key=True)
    source_analysis_type=Column(String(40),index=True)
    source_analysis_id=Column(String(160),index=True)
    relationship_type=Column(String(80),nullable=False)
    status=Column(String(30),nullable=False,default="observed")
    confidence=Column(Float)
    explanation=Column(Text)
    result_json=Column(Text,default="{}")
    first_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class CorrelationAnalysisEvent(Base):
    __tablename__ = "correlation_analysis_events"
    id=Column(Integer,primary_key=True)
    analysis_type=Column(String(40),nullable=False)
    analysis_id=Column(String(160),nullable=False,index=True)
    event_type=Column(String(60),nullable=False)
    actor=Column(String(160),nullable=False,default="system")
    details_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class MessageSimilarityResult(Base):
    __tablename__ = "message_similarity_results"
    id=Column(Integer,primary_key=True)
    source_message_type=Column(String(20),nullable=False)
    source_message_id=Column(String(160),nullable=False,index=True)
    related_message_type=Column(String(20),nullable=False)
    related_message_id=Column(String(160),nullable=False,index=True)
    similarity_score=Column(Float,nullable=False)
    matching_features_json=Column(Text,default="{}")
    detection_method=Column(String(120),nullable=False)
    evidence_json=Column(Text,default="{}")
    model_version=Column(String(160))
    first_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_observed=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("source_message_type","source_message_id","related_message_type","related_message_id",name="uq_message_similarity_pair"),)

class SecurityIncident(Base):
    __tablename__ = "security_incidents"
    id=Column(Integer,primary_key=True)
    incident_key=Column(String(80),unique=True,index=True,nullable=False)
    title=Column(String(255),nullable=False)
    description=Column(Text,default="")
    severity=Column(String(30),default="UNKNOWN")
    status=Column(String(30),default="NEW",index=True)
    first_seen=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_seen=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    updated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class SecurityIncidentSource(Base):
    __tablename__ = "security_incident_sources"
    id=Column(Integer,primary_key=True)
    incident_id=Column(Integer,ForeignKey("security_incidents.id"),index=True,nullable=False)
    source_type=Column(String(40),nullable=False)
    source_id=Column(String(160),nullable=False)
    __table_args__=(UniqueConstraint("source_type","source_id",name="uq_security_incident_source"),)

class IncidentIndicator(Base):
    __tablename__ = "incident_indicators"
    id=Column(Integer,primary_key=True)
    incident_id=Column(Integer,ForeignKey("security_incidents.id"),index=True,nullable=False)
    indicator_id=Column(Integer,ForeignKey("threat_indicators.id"),index=True,nullable=False)
    evidence_json=Column(Text,default="{}")
    __table_args__=(UniqueConstraint("incident_id","indicator_id",name="uq_incident_indicator"),)

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id=Column(Integer,primary_key=True)
    incident_id=Column(Integer,ForeignKey("security_incidents.id"),index=True,nullable=False)
    evidence_type=Column(String(80),nullable=False)
    source=Column(String(120),nullable=False)
    confidence=Column(Float)
    details_json=Column(Text,default="{}")
    observed_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"
    id=Column(Integer,primary_key=True)
    campaign_key=Column(String(160),unique=True,index=True,nullable=False)
    name=Column(String(255),nullable=False)
    description=Column(Text,default="")
    severity=Column(String(30),default="UNKNOWN")
    confidence=Column(Float,default=0)
    status=Column(String(30),default="NEW",index=True)
    first_seen=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    last_seen=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    updated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class CampaignIncident(Base):
    __tablename__ = "campaign_incidents"
    id=Column(Integer,primary_key=True)
    campaign_id=Column(Integer,ForeignKey("threat_campaigns.id"),index=True,nullable=False)
    incident_id=Column(Integer,ForeignKey("security_incidents.id"),index=True,nullable=False)
    confidence=Column(Float)
    explanation=Column(Text)
    association_status=Column(String(30),default="ACTIVE")
    added_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("campaign_id","incident_id",name="uq_campaign_incident"),)

class CampaignIndicator(Base):
    __tablename__ = "campaign_indicators"
    id=Column(Integer,primary_key=True)
    campaign_id=Column(Integer,ForeignKey("threat_campaigns.id"),index=True,nullable=False)
    indicator_id=Column(Integer,ForeignKey("threat_indicators.id"),index=True,nullable=False)
    evidence_json=Column(Text,default="{}")
    __table_args__=(UniqueConstraint("campaign_id","indicator_id",name="uq_campaign_indicator"),)

class CampaignEvidence(Base):
    __tablename__ = "campaign_evidence"
    id=Column(Integer,primary_key=True)
    campaign_id=Column(Integer,ForeignKey("threat_campaigns.id"),index=True,nullable=False)
    evidence_type=Column(String(80),nullable=False)
    source=Column(String(120),nullable=False)
    confidence=Column(Float)
    details_json=Column(Text,default="{}")
    observed_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class CampaignAuditEvent(Base):
    __tablename__ = "campaign_audit_events"
    id=Column(Integer,primary_key=True)
    campaign_id=Column(Integer,ForeignKey("threat_campaigns.id"),index=True,nullable=False)
    actor=Column(String(160),nullable=False)
    action=Column(String(80),nullable=False)
    previous_status=Column(String(30))
    new_status=Column(String(30))
    details_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

class CampaignSummary(Base):
    __tablename__ = "campaign_summaries"
    id=Column(Integer,primary_key=True)
    campaign_id=Column(Integer,ForeignKey("threat_campaigns.id"),index=True,nullable=False)
    campaign_version=Column(String(80),nullable=False)
    summary_text=Column(Text,nullable=False)
    evidence_refs_json=Column(Text,default="[]")
    provider=Column(String(120),nullable=False)
    model=Column(String(160))
    generation_status=Column(String(40),nullable=False)
    generated_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))

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

class ThreatIntelligenceReport(Base):
    __tablename__ = "threat_intelligence_reports"
    id=Column(Integer,primary_key=True)
    report_key=Column(String(160),unique=True,index=True,nullable=False)
    owner_user_id=Column(String(160),index=True,nullable=False)
    title=Column(String(255),nullable=False)
    description=Column(Text,default="")
    status=Column(String(30),nullable=False,default="DRAFT",index=True)
    visibility=Column(String(20),nullable=False,default="PRIVATE")
    published_revision_id=Column(Integer,index=True)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)
    updated_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class ReportRevision(Base):
    __tablename__ = "threat_report_revisions"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True,nullable=False)
    revision_number=Column(Integer,nullable=False)
    previous_revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True)
    canonical_report_hash=Column(String(64),nullable=False,index=True)
    hash_algorithm=Column(String(30),nullable=False,default="SHA-256")
    canonicalization_version=Column(String(30),nullable=False,default="v1")
    canonical_payload=Column(Text,nullable=False)
    revision_metadata_json=Column(Text,default="{}")
    author_user_id=Column(String(160),nullable=False,index=True)
    validation_state=Column(String(30),nullable=False,default="DRAFT",index=True)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)
    published_at=Column(DateTime)
    __table_args__=(UniqueConstraint("report_id","revision_number",name="uq_threat_report_revision_number"),)

class ReportCommitment(Base):
    __tablename__ = "threat_report_commitments"
    id=Column(Integer,primary_key=True)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),unique=True,index=True,nullable=False)
    commitment=Column(String(64),nullable=False,index=True)
    hash_algorithm=Column(String(30),nullable=False,default="SHA-256")
    domain_separator=Column(String(120),nullable=False)
    commitment_scope=Column(String(30),nullable=False,default="LOCAL")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class BlockchainNetwork(Base):
    __tablename__ = "blockchain_networks"
    id=Column(Integer,primary_key=True)
    network_key=Column(String(120),unique=True,index=True,nullable=False)
    name=Column(String(120),nullable=False)
    chain_id=Column(String(120))
    rpc_url=Column(String(2048))
    contract_address=Column(String(255))
    status=Column(String(30),nullable=False,default="CONFIGURED")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class BlockchainTransaction(Base):
    __tablename__ = "blockchain_transactions"
    id=Column(Integer,primary_key=True)
    network_id=Column(Integer,ForeignKey("blockchain_networks.id"),index=True,nullable=False)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True,nullable=False)
    tx_hash=Column(String(255),index=True)
    status=Column(String(30),nullable=False,default="NOT_SUBMITTED")
    block_number=Column(Integer)
    confirmations=Column(Integer,default=0)
    submitted_at=Column(DateTime)
    verified_at=Column(DateTime)
    error=Column(Text)
    metadata_json=Column(Text,default="{}")
    commitment_id=Column(String(160),index=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True)
    block_hash=Column(String(255))
    gas_used=Column(Integer)
    effective_gas_price=Column(String(80))
    confirmation_status=Column(String(30),default="PENDING")
    last_checked_at=Column(DateTime)
    __table_args__=(UniqueConstraint("network_id","revision_id",name="uq_blockchain_tx_revision_network"),)

class WalletIdentity(Base):
    __tablename__ = "wallet_identities"
    id=Column(Integer,primary_key=True)
    owner_user_id=Column(String(160),index=True,nullable=False)
    network_id=Column(Integer,ForeignKey("blockchain_networks.id"),index=True,nullable=False)
    address=Column(String(255),nullable=False)
    verification_status=Column(String(30),nullable=False,default="UNVERIFIED")
    first_verified_at=Column(DateTime)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("network_id","address",name="uq_wallet_network_address"),)

class DigitalSignature(Base):
    __tablename__ = "threat_report_signatures"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True,nullable=False)
    wallet_id=Column(Integer,ForeignKey("wallet_identities.id"),index=True)
    algorithm=Column(String(60),nullable=False)
    signature=Column(Text,nullable=False)
    verification_status=Column(String(30),nullable=False,default="UNVERIFIED")
    signature_type=Column(String(40),nullable=False,default="EIP712")
    purpose=Column(String(80),nullable=False,default="REPORT_REVISION")
    chain_id=Column(String(80))
    nonce=Column(String(160),index=True)
    expires_at=Column(DateTime)
    verified_at=Column(DateTime)
    evidence_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

class WalletChallenge(Base):
    __tablename__ = "wallet_challenges"
    id=Column(Integer,primary_key=True)
    challenge_id=Column(String(160),unique=True,index=True,nullable=False)
    owner_user_id=Column(String(160),index=True,nullable=False)
    wallet_address=Column(String(255),nullable=False,index=True)
    domain=Column(String(255),nullable=False)
    action=Column(String(80),nullable=False)
    chain_id=Column(String(80),nullable=False)
    nonce=Column(String(160),unique=True,index=True,nullable=False)
    message=Column(Text,nullable=False)
    typed_data_json=Column(Text)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True)
    report_hash=Column(String(64))
    expires_at=Column(DateTime,nullable=False,index=True)
    consumed_at=Column(DateTime)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class EvidenceObject(Base):
    __tablename__ = "threat_evidence_objects"
    id=Column(Integer,primary_key=True)
    owner_user_id=Column(String(160),index=True,nullable=False)
    object_hash=Column(String(64),index=True,nullable=False)
    hash_algorithm=Column(String(30),nullable=False,default="SHA-256")
    storage_uri=Column(String(2048))
    content_type=Column(String(160))
    size_bytes=Column(Integer)
    metadata_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("owner_user_id","object_hash",name="uq_threat_evidence_owner_hash"),)

class EvidenceReference(Base):
    __tablename__ = "threat_evidence_references"
    id=Column(Integer,primary_key=True)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True,nullable=False)
    evidence_object_id=Column(Integer,ForeignKey("threat_evidence_objects.id"),index=True,nullable=False)
    reference_type=Column(String(80),nullable=False,default="SUPPORTING")
    description=Column(Text,default="")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint("revision_id","evidence_object_id","reference_type",name="uq_threat_evidence_reference"),)

class ProvenanceEvent(Base):
    __tablename__ = "threat_provenance_events"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True,nullable=False)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True)
    actor_user_id=Column(String(160),index=True,nullable=False)
    event_type=Column(String(80),nullable=False)
    details_json=Column(Text,default="{}")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class ValidationRecord(Base):
    __tablename__ = "threat_validation_records"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True,nullable=False)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True,nullable=False)
    validator_user_id=Column(String(160),index=True,nullable=False)
    validation_state=Column(String(30),nullable=False)
    notes=Column(Text,default="")
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class DisputeRecord(Base):
    __tablename__ = "threat_dispute_records"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True,nullable=False)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True)
    opened_by=Column(String(160),index=True,nullable=False)
    status=Column(String(30),nullable=False,default="OPEN")
    reason=Column(Text,nullable=False)
    resolution=Column(Text)
    created_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)
    resolved_at=Column(DateTime)

class AppendOnlyLedgerEvent(Base):
    __tablename__ = "threat_append_only_ledger_events"
    id=Column(Integer,primary_key=True)
    event_type=Column(String(80),nullable=False)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True)
    actor_user_id=Column(String(160),nullable=False)
    payload_hash=Column(String(64),nullable=False)
    previous_event_hash=Column(String(64))
    event_hash=Column(String(64),unique=True,index=True,nullable=False)
    payload_json=Column(Text,nullable=False)
    sequence_number=Column(Integer,index=True,nullable=False,default=0)
    hash_algorithm=Column(String(30),nullable=False,default="SHA-256")
    hash_version=Column(String(30),nullable=False,default="v2")
    evidence_refs_json=Column(Text,default="[]")
    dedupe_key=Column(String(255),unique=True,index=True)
    occurred_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)

class LedgerSequenceState(Base):
    __tablename__ = "threat_ledger_sequence_state"
    id=Column(Integer,primary_key=True)
    next_sequence=Column(Integer,nullable=False,default=1)
    updated_at=Column(DateTime,default=lambda:datetime.now(timezone.utc))

@event.listens_for(Base, "before_update", propagate=True)
def _prevent_ledger_update(mapper, connection, target):
    if isinstance(target, AppendOnlyLedgerEvent) and not getattr(target, "_ledger_initializing", False):
        raise ValueError("append-only ledger events cannot be updated")

@event.listens_for(Base, "before_delete", propagate=True)
def _prevent_ledger_delete(mapper, connection, target):
    if isinstance(target, AppendOnlyLedgerEvent):
        raise ValueError("append-only ledger events cannot be deleted")

class IntegrityVerificationRecord(Base):
    __tablename__ = "threat_integrity_verifications"
    id=Column(Integer,primary_key=True)
    report_id=Column(Integer,ForeignKey("threat_intelligence_reports.id"),index=True,nullable=False)
    revision_id=Column(Integer,ForeignKey("threat_report_revisions.id"),index=True,nullable=False)
    commitment=Column(String(64),nullable=False)
    verification_source=Column(String(120),nullable=False)
    status=Column(String(30),nullable=False)
    details_json=Column(Text,default="{}")
    verified_at=Column(DateTime,default=lambda:datetime.now(timezone.utc),index=True)
