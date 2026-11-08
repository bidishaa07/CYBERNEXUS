"""Persistence primitives for Phase 4.1 correlation data."""
import json
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from backend.app.models.models import ThreatIndicator, IndicatorObservation, IndicatorRelationship, CorrelationEvidence, CorrelationResult, CorrelationAnalysisEvent
from backend.app.engines.indicator_normalization import normalize_indicator

def _now():
    return datetime.now(timezone.utc)

def get_or_create_indicator(db, indicator_type, value, *, source=None, category=None, verification_status="unknown", confidence=None):
    kind, normalized = normalize_indicator(indicator_type, value)
    row = db.query(ThreatIndicator).filter(ThreatIndicator.indicator_type == kind, ThreatIndicator.indicator == normalized).first()
    if row is None:
        row = ThreatIndicator(indicator=normalized, indicator_type=kind, category=category, confidence=confidence or 0, verification_status=verification_status, source=source)
        db.add(row)
        try:
            with db.begin_nested():
                db.flush()
        except IntegrityError:
            row = db.query(ThreatIndicator).filter(ThreatIndicator.indicator_type == kind, ThreatIndicator.indicator == normalized).first()
            if row is None:
                raise
    else:
        row.last_seen = _now()
        if source and not row.source:
            row.source = source
    return row

def record_observation(db, indicator_type, value, *, source_analysis_type, source_analysis_id, source_provider=None, verification_status="unknown", confidence=None, metadata=None):
    original = str(value)
    indicator = get_or_create_indicator(db, indicator_type, original, source=source_provider, verification_status=verification_status, confidence=confidence)
    now = _now()
    row = db.query(IndicatorObservation).filter_by(indicator_id=indicator.id, source_analysis_type=source_analysis_type, source_analysis_id=str(source_analysis_id), normalized_value=indicator.indicator).first()
    if row:
        row.last_observed = now
        row.observation_count = (row.observation_count or 0) + 1
        row.metadata_json = json.dumps(metadata or {})
    else:
        row = IndicatorObservation(indicator_id=indicator.id, source_analysis_type=source_analysis_type, source_analysis_id=str(source_analysis_id), normalized_value=indicator.indicator, original_observed_value=original, source_provider=source_provider, verification_status=verification_status, confidence=confidence, metadata_json=json.dumps(metadata or {}), first_observed=now, last_observed=now, observation_count=1)
        db.add(row)
    db.flush()
    return indicator, row

def record_relationship(db, source_indicator, target_indicator, relationship_type, *, analysis_type=None, analysis_id=None, confidence=None, status="observed"):
    row = db.query(IndicatorRelationship).filter_by(source_indicator_id=source_indicator.id, target_indicator_id=target_indicator.id, relationship_type=relationship_type).first()
    now = _now()
    if row:
        row.last_observed = now
        if confidence is not None:
            row.confidence = max(row.confidence or 0, confidence)
    else:
        row = IndicatorRelationship(source_indicator_id=source_indicator.id, target_indicator_id=target_indicator.id, relationship_type=relationship_type, status=status, confidence=confidence, originating_analysis_type=analysis_type, originating_analysis_id=str(analysis_id) if analysis_id is not None else None, first_observed=now, last_observed=now)
        db.add(row)
        db.flush()
    return row

def record_evidence(db, *, relationship_id=None, result_id=None, evidence_type, source, details=None, confidence=None):
    details_json = json.dumps(details or {}, sort_keys=True)
    row = db.query(CorrelationEvidence).filter_by(relationship_id=relationship_id, result_id=result_id, evidence_type=evidence_type, source=source, details_json=details_json).first()
    if row:
        row.confidence = confidence
        row.observed_at = _now()
    else:
        row = CorrelationEvidence(relationship_id=relationship_id, result_id=result_id, evidence_type=evidence_type, source=source, details_json=details_json, confidence=confidence)
        db.add(row); db.flush()
    return row

def record_event(db, analysis_type, analysis_id, event_type, *, actor="system", details=None):
    row = CorrelationAnalysisEvent(analysis_type=analysis_type, analysis_id=str(analysis_id), event_type=event_type, actor=actor, details_json=json.dumps(details or {}))
    db.add(row); db.flush(); return row
