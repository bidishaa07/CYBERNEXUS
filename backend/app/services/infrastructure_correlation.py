"""Evidence-backed multi-indicator infrastructure correlation.

This module creates domain-to-domain relationships only when two domains were
observed with the same normalized indicator. Shared infrastructure is an
association, never an ownership or maliciousness verdict.
"""
import json
from collections import defaultdict
from datetime import datetime, timezone

from backend.app.engines.indicator_normalization import normalize_indicator
from backend.app.models.models import (
    CertificateRecord, CorrelationEvidence, DomainIntelligence,
    IndicatorObservation, MessageIndicatorResult, Scan, WebsiteImageCandidate,
    ThreatIndicator,
)
from backend.app.services.correlation_data import record_evidence, record_observation, record_relationship
from backend.app.core.config import settings

DEFAULT_CONFIDENCE = {
    "shared_ip": 0.35,
    "shared_asn": 0.25,
    "shared_nameserver": 0.25,
    "shared_certificate": 0.92,
    "shared_favicon": 0.82,
    "shared_content": 0.72,
    "shared_payment_destination": 0.95,
}

def _confidence(key):
    try:
        configured = json.loads(settings.correlation_confidence_weights_json or "{}")
        value = float(configured.get(key, DEFAULT_CONFIDENCE[key]))
        return max(0.0, min(1.0, value))
    except (TypeError, ValueError, KeyError):
        return DEFAULT_CONFIDENCE[key]

def _now():
    return datetime.now(timezone.utc)

def _json(value):
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}

def _source_key(source_type, source_id):
    return source_type, str(source_id)

def _safe_record(db, kind, value, *, source_type, source_id, source="existing_scan", metadata=None):
    try:
        return record_observation(db, kind, value, source_analysis_type=source_type, source_analysis_id=source_id, source_provider=source, metadata=metadata)[0]
    except ValueError:
        return None

def ingest_existing_evidence(db):
    """Index existing scan/message records without inventing missing indicators."""
    domains_by_source = {}
    for scan in db.query(Scan).all():
        source = _source_key("scan", scan.id)
        domain = _safe_record(db, "DOMAIN", scan.domain or scan.url, source_type=source[0], source_id=source[1], metadata={"url": scan.url})
        if domain:
            domains_by_source[source] = domain
        result = _json(scan.result_json)
        intel = result.get("domain_intelligence") or {}
        infra = intel.get("infrastructure") or result.get("infrastructure") or {}
        for ip in infra.get("ips") or []:
            _safe_record(db, "IP_ADDRESS", ip, source_type=source[0], source_id=source[1], metadata={"domain": scan.domain})
        for provider in infra.get("providers") or []:
            if provider.get("asn_number"):
                _safe_record(db, "ASN", provider["asn_number"], source_type=source[0], source_id=source[1], metadata=provider)
        rdap = intel.get("rdap") or {}
        for nameserver in rdap.get("nameservers") or []:
            _safe_record(db, "NAMESERVER", nameserver, source_type=source[0], source_id=source[1], metadata={"domain": scan.domain})
        for cert in db.query(CertificateRecord).filter(CertificateRecord.scan_id == scan.id).all():
            _safe_record(db, "CERTIFICATE_FINGERPRINT", cert.fingerprint_sha256, source_type=source[0], source_id=source[1], metadata={"subject": cert.subject, "issuer": cert.issuer, "role": cert.role})
        for candidate in db.query(WebsiteImageCandidate).filter(WebsiteImageCandidate.scan_id == scan.id).all():
            asset_type = (candidate.asset_type or "").lower()
            if candidate.sha256:
                kind = "FAVICON_HASH" if asset_type == "favicon" else "CONTENT_FINGERPRINT" if asset_type == "content" else None
                if kind:
                    _safe_record(db, kind, candidate.sha256, source_type=source[0], source_id=source[1], metadata={"asset_type": asset_type, "source_url": candidate.source_url})
            if asset_type == "favicon" and candidate.phash:
                _safe_record(db, "FAVICON_HASH", candidate.phash, source_type=source[0], source_id=source[1], source="favicon-phash", metadata={"algorithm": "phash"})

    for row in db.query(MessageIndicatorResult).all():
        kind = (row.indicator_type or "").upper()
        mapped = {"PAYMENT": "PAYMENT_DESTINATION", "URL": "URL", "DOMAIN": "DOMAIN", "EMAIL": "EMAIL_ADDRESS", "PHONE": "PHONE_NUMBER"}.get(kind)
        if mapped:
            _safe_record(db, mapped, row.indicator, source_type="message" if row.message_analysis_id else "email", source_id=row.message_analysis_id or row.email_analysis_id, source=row.provider, metadata=_json(row.result_json))
    db.flush()
    return domains_by_source

def _correlate_shared(db, *, indicator_kind, relationship_type, confidence_key, explanation, match_predicate=None):
    """Create deduplicated domain relationships for a shared indicator kind."""
    rows = db.query(IndicatorObservation).filter(IndicatorObservation.source_analysis_type == "scan").all()
    domain_by_source = {}
    for row in rows:
        if row.indicator_id and row.normalized_value and row.source_analysis_id:
            # DOMAIN rows are identified by their canonical indicator type through
            # a lightweight query below; this avoids relying on ORM relationships.
            indicator = db.get(ThreatIndicator, row.indicator_id)
            if indicator and indicator.indicator_type == "DOMAIN":
                domain_by_source[row.source_analysis_id] = row
    candidates = defaultdict(list)
    for row in rows:
        indicator = db.get(ThreatIndicator, row.indicator_id)
        if indicator and indicator.indicator_type == indicator_kind:
            candidates[row.normalized_value].append(row.source_analysis_id)
    created = []
    for matching_value, source_ids in candidates.items():
        unique_sources = sorted(set(source_ids))
        if len(unique_sources) < 2:
            continue
        for index, left_source in enumerate(unique_sources):
            for right_source in unique_sources[index + 1:]:
                left = domain_by_source.get(left_source); right = domain_by_source.get(right_source)
                if not left or not right or left.indicator_id == right.indicator_id:
                    continue
                if match_predicate and not match_predicate(matching_value):
                    continue
                score = _confidence(confidence_key)
                relationship = record_relationship(db, left_indicator(db, left), left_indicator(db, right), relationship_type, analysis_type="scan", analysis_id=left_source, confidence=score)
                evidence = record_evidence(db, relationship_id=relationship.id, evidence_type=relationship_type, source=f"{indicator_kind.lower()}_observation", details={"matching_indicator": matching_value, "source_scans": [left_source, right_source], "explanation": explanation}, confidence=score)
                created.append({"relationship_id": relationship.id, "relationship_type": relationship_type, "source_domain": left.normalized_value, "target_domain": right.normalized_value, "matching_indicator": matching_value, "confidence": evidence.confidence, "explanation": explanation, "first_observed": relationship.first_observed, "last_observed": relationship.last_observed})
    return created

def left_indicator(db, observation):
    return db.get(ThreatIndicator, observation.indicator_id)

class SharedIPAddressCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="IP_ADDRESS", relationship_type="shared_ip", confidence_key="shared_ip", explanation="Domains were observed resolving to the same IP address; shared hosting or CDN use can explain this relationship, which does not establish ownership or maliciousness.")

class SharedASNCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="ASN", relationship_type="shared_asn", confidence_key="shared_asn", explanation="Domains were observed in the same ASN; common hosting or cloud infrastructure can explain this relationship, which does not establish ownership or maliciousness.")

class SharedNameserverCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="NAMESERVER", relationship_type="shared_nameserver", confidence_key="shared_nameserver", explanation="Domains were observed using the same nameserver; common DNS providers are not evidence of shared ownership or maliciousness.")

class SharedCertificateCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="CERTIFICATE_FINGERPRINT", relationship_type="shared_certificate_fingerprint", confidence_key="shared_certificate", explanation="Domains were observed with the same certificate fingerprint.")

class SharedFaviconCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="FAVICON_HASH", relationship_type="shared_favicon_hash", confidence_key="shared_favicon", explanation="Domains were observed with the same favicon hash; this is supporting identity evidence, not proof of ownership.")

class SharedContentCorrelationService:
    @staticmethod
    def run(db):
        return _correlate_shared(db, indicator_kind="CONTENT_FINGERPRINT", relationship_type="shared_content_fingerprint", confidence_key="shared_content", explanation="Domains were observed with the same content fingerprint.")

class SharedPaymentDestinationCorrelationService:
    @staticmethod
    def run(db):
        payments = defaultdict(list)
        for row in db.query(IndicatorObservation).all():
            indicator = db.get(ThreatIndicator, row.indicator_id)
            if indicator and indicator.indicator_type == "PAYMENT_DESTINATION" and row.source_analysis_type in {"message", "email"}:
                payments[row.normalized_value].append(row.source_analysis_id)
        results = []
        for matching_value, source_ids in payments.items():
            unique_sources = sorted(set(source_ids))
            if len(unique_sources) < 2:
                continue
            source_indicators = {}
            for source_id in unique_sources:
                source_indicators[source_id] = _safe_record(db, "MESSAGE_IDENTIFIER", source_id, source_type="message", source_id=source_id, source="message-analysis")
            for index, left_source in enumerate(unique_sources):
                for right_source in unique_sources[index + 1:]:
                    left = source_indicators.get(left_source); right = source_indicators.get(right_source)
                    if not left or not right or left.id == right.id:
                        continue
                    score = _confidence("shared_payment_destination")
                    relationship = record_relationship(db, left, right, "shared_payment_destination", analysis_type="message", analysis_id=left_source, confidence=score)
                    evidence = record_evidence(db, relationship_id=relationship.id, evidence_type="shared_payment_destination", source="payment_observation", details={"matching_indicator": matching_value, "source_analyses": [left_source, right_source], "explanation": "Messages referenced the same typed payment destination; no transaction was initiated."}, confidence=score)
                    results.append({"relationship_id": relationship.id, "relationship_type": relationship.relationship_type, "source_analysis": left_source, "target_analysis": right_source, "matching_indicator": matching_value, "confidence": evidence.confidence, "explanation": "Messages referenced the same typed payment destination; no transaction was initiated.", "first_observed": relationship.first_observed, "last_observed": relationship.last_observed})
        return results

SERVICES = (SharedIPAddressCorrelationService, SharedASNCorrelationService, SharedNameserverCorrelationService, SharedCertificateCorrelationService, SharedFaviconCorrelationService, SharedContentCorrelationService, SharedPaymentDestinationCorrelationService)

def run_infrastructure_correlation(db):
    ingest_existing_evidence(db)
    results = []
    for service in SERVICES:
        results.extend(service.run(db))
    db.commit()
    return {"relationships": results, "count": len(results), "method": "evidence-backed shared-indicator correlation", "generated_at": _now().isoformat(), "limitations": ["Shared IP, ASN and nameserver relationships do not establish ownership or maliciousness.", "Perceptual similarity is not used as exact equality in this phase.", "Missing or unavailable intelligence does not create a clean verdict."]}
