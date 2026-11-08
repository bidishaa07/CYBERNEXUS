"""Persistent, explainable incident discovery and campaign grouping."""
import hashlib
import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from backend.app.core.config import settings
from backend.app.models.models import (
    CampaignAuditEvent, CampaignEvidence, CampaignIncident, CampaignIndicator,
    CorrelationEvidence, IndicatorObservation, IndicatorRelationship,
    IncidentEvidence, IncidentIndicator, MessageAnalysisMetadata,
    MessageSimilarityResult, Scan, SecurityIncident, SecurityIncidentSource,
    ThreatCampaign, ThreatIndicator,
)

INCIDENT_STATUSES = {"NEW", "INVESTIGATING", "CONFIRMED", "RESOLVED", "FALSE_POSITIVE"}
CAMPAIGN_STATUSES = INCIDENT_STATUSES

def _now():
    return datetime.now(timezone.utc)

def _json(value):
    try: return json.loads(value or "{}")
    except (TypeError, ValueError): return {}

def _source(source_type, source_id):
    return source_type.lower(), str(source_id)

def _ensure_incident(db, source_type, source_id, title, seen_at=None):
    source_type, source_id = _source(source_type, source_id)
    source = db.query(SecurityIncidentSource).filter_by(source_type=source_type, source_id=source_id).first()
    now = seen_at or _now()
    if source:
        incident = db.get(SecurityIncident, source.incident_id)
        incident.last_seen = now; incident.updated_at = now
        return incident
    incident = SecurityIncident(incident_key=f"{source_type}:{source_id}", title=title, description="Discovered from an existing persisted analysis; grouping is evidence-based and reversible.", severity="UNKNOWN", status="NEW", first_seen=now, last_seen=now, created_at=now, updated_at=now)
    db.add(incident); db.flush()
    db.add(SecurityIncidentSource(incident_id=incident.id, source_type=source_type, source_id=source_id))
    return incident

def _discover_incidents(db):
    incidents = {}
    for row in db.query(MessageAnalysisMetadata).all():
        kind = "TEXT" if row.message_analysis_id else "EML"
        identifier = str(row.message_analysis_id or row.email_analysis_id)
        incidents[("message", f"{kind.lower()}:{identifier}")] = _ensure_incident(db, "message", f"{kind.lower()}:{identifier}", f"Message analysis {kind}:{identifier}", row.created_at)
    for row in db.query(Scan).all():
        incidents[("scan", str(row.id))] = _ensure_incident(db, "scan", row.id, f"Website scan {row.domain}", row.created_at)
    db.flush()
    return incidents

def _incident_indicators(db, incidents):
    for row in db.query(IndicatorObservation).all():
        key = _source(row.source_analysis_type, row.source_analysis_id)
        incident = incidents.get(key)
        if not incident:
            continue
        existing = db.query(IncidentIndicator).filter_by(incident_id=incident.id, indicator_id=row.indicator_id).first()
        if not existing:
            db.add(IncidentIndicator(incident_id=incident.id, indicator_id=row.indicator_id, evidence_json=json.dumps({"source_analysis_type": row.source_analysis_type, "source_analysis_id": row.source_analysis_id, "observed_at": row.last_observed}, default=str)))

def _message_similarity_edges(db, incidents):
    edges = []
    for row in db.query(MessageSimilarityResult).all():
        left = incidents.get(("message", f"{row.source_message_type.lower()}:{row.source_message_id}"))
        right = incidents.get(("message", f"{row.related_message_type.lower()}:{row.related_message_id}"))
        if not left or not right:
            continue
        edges.append((left.id, right.id, float(row.similarity_score or 0), "message_similarity", {"similarity_score": row.similarity_score, "matching_features": _json(row.matching_features_json), "evidence": _json(row.evidence_json)}))
    return edges

def _shared_evidence_edges(db, incidents):
    edges = []
    for evidence in db.query(CorrelationEvidence).all():
        details = _json(evidence.details_json)
        sources = []
        for key in ("source_scans", "source_analyses"):
            sources.extend(details.get(key) or [])
        normalized = []
        for source_type, source_id in ((key, item) for key in ("source_scans", "source_analyses") for item in (details.get(key) or [])):
            text = str(source_id)
            if source_type == "source_analyses" or text.lower().startswith(("text:", "eml:")):
                normalized.append(incidents.get(("message", text.lower())))
            else:
                normalized.append(incidents.get(("scan", text)))
        normalized = [item for item in normalized if item]
        if len(normalized) >= 2:
            for index, left in enumerate(normalized):
                for right in normalized[index + 1:]:
                    edges.append((left.id, right.id, float(evidence.confidence or 0), evidence.evidence_type, details))
    return edges

def _edge_groups(edges, threshold):
    pair_types = defaultdict(set)
    pair_edges = defaultdict(list)
    parent = {}
    def find(value):
        parent.setdefault(value, value)
        if parent[value] != value: parent[value] = find(parent[value])
        return parent[value]
    def union(left, right):
        left, right = find(left), find(right)
        if left != right: parent[right] = left
    for left, right, score, kind, details in edges:
        pair = tuple(sorted((left, right))); pair_types[pair].add(kind); pair_edges[pair].append((score, kind, details)); find(left); find(right)
    for pair, evidence in pair_edges.items():
        strongest = max(item[0] for item in evidence)
        # A weak infrastructure relationship is insufficient by itself. Two
        # independent relationship types can support grouping.
        if strongest >= threshold or len(pair_types[pair]) >= 2:
            union(*pair)
    groups = defaultdict(list)
    for incident_id in parent:
        groups[find(incident_id)].append(incident_id)
    return [sorted(values) for values in groups.values() if len(values) >= 2], pair_edges

def _severity(confidence):
    if confidence >= .9: return "HIGH"
    if confidence >= .7: return "MEDIUM"
    return "LOW"

def _campaign_for(db, component):
    digest = hashlib.sha256(",".join(map(str, component)).encode()).hexdigest()[:24]
    return db.query(ThreatCampaign).filter_by(campaign_key=f"discovered:{digest}").first()

def _upsert_campaign(db, component, edges_by_pair, incidents_by_id):
    component_set = set(component)
    supporting = []
    for pair, evidence in edges_by_pair.items():
        if set(pair) <= component_set:
            supporting.extend(evidence)
    confidence = max((item[0] for item in supporting), default=0)
    independent_types = len({item[1] for item in supporting})
    if independent_types > 1:
        confidence = min(1.0, confidence + .05 * (independent_types - 1))
    campaign = _campaign_for(db, component)
    now = _now()
    if not campaign:
        campaign = ThreatCampaign(campaign_key=f"discovered:{hashlib.sha256(','.join(map(str, component)).encode()).hexdigest()[:24]}", name=f"Observed threat campaign {component[0]}", description="Incidents grouped from independent persisted correlation evidence; membership is not a confirmed malicious verdict.", severity=_severity(confidence), confidence=confidence, status="NEW", first_seen=now, last_seen=now, created_at=now, updated_at=now)
        db.add(campaign); db.flush()
    else:
        campaign.confidence = max(campaign.confidence or 0, confidence); campaign.last_seen = now; campaign.updated_at = now
    for incident_id in component:
        relation = db.query(CampaignIncident).filter_by(campaign_id=campaign.id, incident_id=incident_id).first()
        if not relation:
            relation = CampaignIncident(campaign_id=campaign.id, incident_id=incident_id, confidence=confidence, explanation="; ".join(sorted({item[1] for item in supporting})) or "Evidence-backed relationship", association_status="ACTIVE", added_at=now); db.add(relation)
    for score, kind, details in supporting:
        db.add(CampaignEvidence(campaign_id=campaign.id, evidence_type=kind, source="correlation-engine", confidence=score, details_json=json.dumps(details, default=str), observed_at=now))
    attached_indicators = {row.indicator_id for row in db.query(CampaignIndicator).filter_by(campaign_id=campaign.id).all()}
    for incident_id in component:
        for row in db.query(IncidentIndicator).filter_by(incident_id=incident_id).all():
            if row.indicator_id not in attached_indicators:
                db.add(CampaignIndicator(campaign_id=campaign.id, indicator_id=row.indicator_id, evidence_json=row.evidence_json)); attached_indicators.add(row.indicator_id)
    return campaign

def group_incidents(db, threshold=None):
    incidents = _discover_incidents(db); _incident_indicators(db, incidents)
    edges = _message_similarity_edges(db, incidents) + _shared_evidence_edges(db, incidents)
    components, edge_map = _edge_groups(edges, settings.campaign_grouping_threshold if threshold is None else threshold)
    campaigns = [_upsert_campaign(db, component, edge_map, incidents) for component in components]
    db.commit()
    return {"incidents": [{"id": row.id, "incident_key": row.incident_key, "status": row.status, "severity": row.severity, "title": row.title, "first_seen": row.first_seen, "last_seen": row.last_seen} for row in incidents.values()], "campaigns": [{"id": row.id, "campaign_key": row.campaign_key, "status": row.status, "severity": row.severity, "confidence": row.confidence, "name": row.name, "first_seen": row.first_seen, "last_seen": row.last_seen} for row in campaigns], "campaign_count": len(campaigns), "incident_count": len(incidents), "threshold": threshold if threshold is not None else settings.campaign_grouping_threshold, "method": "evidence-backed grouping; weak shared infrastructure alone is insufficient"}

def set_campaign_status(db, campaign_id, status, actor, details=None):
    if status not in CAMPAIGN_STATUSES: raise ValueError("invalid campaign status")
    campaign = db.get(ThreatCampaign, campaign_id)
    if not campaign: raise LookupError("campaign not found")
    previous = campaign.status; campaign.status = status; campaign.updated_at = _now()
    db.add(CampaignAuditEvent(campaign_id=campaign.id, actor=actor, action="status_changed", previous_status=previous, new_status=status, details_json=json.dumps(details or {})))
    db.commit(); return campaign

def reject_campaign_incident(db, campaign_id, incident_id, actor, reason=""):
    relation = db.query(CampaignIncident).filter_by(campaign_id=campaign_id, incident_id=incident_id).first()
    if not relation: raise LookupError("campaign relationship not found")
    relation.association_status = "REJECTED"
    db.add(CampaignAuditEvent(campaign_id=campaign_id, actor=actor, action="relationship_rejected", details_json=json.dumps({"incident_id": incident_id, "reason": reason})))
    db.commit(); return relation

def merge_campaigns(db, target_id, source_id, actor, reason=""):
    if target_id == source_id: raise ValueError("target and source campaigns must differ")
    target, source = db.get(ThreatCampaign, target_id), db.get(ThreatCampaign, source_id)
    if not target or not source: raise LookupError("campaign not found")
    for relation in db.query(CampaignIncident).filter_by(campaign_id=source.id, association_status="ACTIVE").all():
        existing = db.query(CampaignIncident).filter_by(campaign_id=target.id, incident_id=relation.incident_id).first()
        if existing:
            relation.association_status = "MERGED"
        else:
            relation.campaign_id = target.id
    target.confidence = max(target.confidence or 0, source.confidence or 0); target.last_seen = max(target.last_seen or _now(), source.last_seen or _now()); target.updated_at = _now()
    previous = source.status; source.status = "RESOLVED"; source.updated_at = _now()
    db.add(CampaignAuditEvent(campaign_id=target.id, actor=actor, action="campaign_merged", details_json=json.dumps({"source_campaign_id": source.id, "reason": reason})))
    db.add(CampaignAuditEvent(campaign_id=source.id, actor=actor, action="campaign_merged_into", previous_status=previous, new_status=source.status, details_json=json.dumps({"target_campaign_id": target.id, "reason": reason})))
    db.commit(); return target

def split_campaign(db, campaign_id, incident_ids, actor, reason=""):
    campaign = db.get(ThreatCampaign, campaign_id)
    if not campaign: raise LookupError("campaign not found")
    requested = {int(item) for item in incident_ids}
    relations = [row for row in db.query(CampaignIncident).filter_by(campaign_id=campaign.id, association_status="ACTIVE").all() if row.incident_id in requested]
    if not relations: raise ValueError("no active incident relationships selected")
    new = ThreatCampaign(campaign_key=f"manual-split:{uuid.uuid4().hex}", name=f"{campaign.name} — split", description="Created by an authorized analyst split action.", severity=campaign.severity, confidence=campaign.confidence, status="NEW", first_seen=campaign.first_seen, last_seen=campaign.last_seen, created_at=_now(), updated_at=_now())
    db.add(new); db.flush()
    for relation in relations:
        relation.association_status = "SPLIT"
        db.add(CampaignIncident(campaign_id=new.id, incident_id=relation.incident_id, confidence=relation.confidence, explanation=relation.explanation, association_status="ACTIVE", added_at=_now()))
    db.add(CampaignAuditEvent(campaign_id=campaign.id, actor=actor, action="campaign_split", details_json=json.dumps({"new_campaign_id": new.id, "incident_ids": sorted(requested), "reason": reason})))
    db.add(CampaignAuditEvent(campaign_id=new.id, actor=actor, action="campaign_split_created", details_json=json.dumps({"source_campaign_id": campaign.id, "incident_ids": sorted(requested), "reason": reason})))
    db.commit(); return new

def list_campaigns(db):
    return [{"id": row.id, "campaign_key": row.campaign_key, "name": row.name, "description": row.description, "severity": row.severity, "confidence": row.confidence, "status": row.status, "incident_ids": [x.incident_id for x in db.query(CampaignIncident).filter_by(campaign_id=row.id, association_status="ACTIVE").all()], "first_seen": row.first_seen, "last_seen": row.last_seen} for row in db.query(ThreatCampaign).order_by(ThreatCampaign.updated_at.desc()).all()]
