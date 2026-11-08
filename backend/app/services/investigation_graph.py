"""Evidence-preserving campaign/incident graph and timeline projections."""
import json
from collections import defaultdict
from datetime import datetime, timezone

from backend.app.models.models import (
    CampaignAuditEvent, CampaignEvidence, CampaignIncident, CampaignIndicator,
    IncidentEvidence, IncidentIndicator, MessageAnalysisMetadata,
    MessageSimilarityResult, SecurityIncident, SecurityIncidentSource,
    ThreatCampaign, ThreatIndicator,
)

def _json(value):
    try: return json.loads(value or "{}")
    except (TypeError, ValueError): return {}

def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value

def _node(nodes, node_id, kind, label, data=None):
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": kind, "label": label, "data": data or {}}
    return node_id

def _edge(edges, source, target, relationship, confidence, evidence, first_observed=None, last_observed=None, status="observed"):
    key=(source,target,relationship)
    if key not in edges:
        edges[key] = {"id": f"{source}:{target}:{relationship}", "source": source, "target": target, "relationship_type": relationship, "confidence": confidence, "status": status, "evidence": evidence or {}, "first_observed": _iso(first_observed), "last_observed": _iso(last_observed)}
    return edges[key]

def _incident_sources(db, incident_id):
    return db.query(SecurityIncidentSource).filter_by(incident_id=incident_id).all()

def _add_source_node(db, nodes, edges, incident, source):
    kind = "message" if source.source_type == "message" else "scan"
    node_id = f"{kind}:{source.source_id}"
    label = f"{kind.title()} {source.source_id}"
    metadata = db.query(MessageAnalysisMetadata).filter(MessageAnalysisMetadata.message_analysis_id == source.source_id.split(":")[-1]).first() if kind == "message" and source.source_id.startswith("text:") else None
    if metadata: label = metadata.subject or metadata.sender or label
    _node(nodes, node_id, kind, label, {"source_type": source.source_type, "source_id": source.source_id})
    _edge(edges, f"incident:{incident.id}", node_id, "incident_association", .98, {"source": "security_incident_sources", "source_type": source.source_type, "source_id": source.source_id}, incident.first_seen, incident.last_seen)

def _add_incident(db, nodes, edges, incident):
    _node(nodes, f"incident:{incident.id}", "incident", incident.title, {"status": incident.status, "severity": incident.severity, "description": incident.description})
    for source in _incident_sources(db, incident.id):
        _add_source_node(db, nodes, edges, incident, source)
    for link in db.query(IncidentIndicator).filter_by(incident_id=incident.id).all():
        indicator = db.get(ThreatIndicator, link.indicator_id)
        if not indicator: continue
        indicator_node = f"indicator:{indicator.id}"
        _node(nodes, indicator_node, indicator.indicator_type.lower(), indicator.indicator, {"normalized_value": indicator.indicator, "verification_status": indicator.verification_status, "source": indicator.source})
        _edge(edges, f"incident:{incident.id}", indicator_node, "shared_indicator", 1.0, _json(link.evidence_json), incident.first_seen, incident.last_seen, link.evidence_json and "observed")

def _campaign_graph(db, campaign, max_nodes=500):
    nodes={}; edges={}
    _node(nodes, f"campaign:{campaign.id}", "campaign", campaign.name, {"status": campaign.status, "severity": campaign.severity, "confidence": campaign.confidence, "description": campaign.description})
    relations=db.query(CampaignIncident).filter_by(campaign_id=campaign.id).all()
    for relation in relations:
        incident=db.get(SecurityIncident, relation.incident_id)
        if not incident: continue
        _add_incident(db,nodes,edges,incident)
        _edge(edges,f"campaign:{campaign.id}",f"incident:{incident.id}","campaign_membership",relation.confidence or campaign.confidence,_json(relation.explanation) if relation.explanation and relation.explanation.startswith("{") else {"explanation": relation.explanation},relation.added_at,incident.last_seen,relation.association_status.lower())
    for evidence in db.query(CampaignEvidence).filter_by(campaign_id=campaign.id).all():
        details=_json(evidence.details_json)
        for pair in details.get("source_analyses",[]) or []:
            _node(nodes,f"message:{str(pair).lower()}","message",f"Message {pair}",{"source_analysis":pair})
    # Connect message pairs using persisted Phase 4.3 results.
    message_ids={source.source_id for relation in relations for source in _incident_sources(db,relation.incident_id) if source.source_type=="message"}
    for row in db.query(MessageSimilarityResult).all():
        left=f"{row.source_message_type.lower()}:{row.source_message_id}"; right=f"{row.related_message_type.lower()}:{row.related_message_id}"
        if left in message_ids or right in message_ids:
            _node(nodes,f"message:{left}","message",f"Message {left}",{"source_analysis":left}); _node(nodes,f"message:{right}","message",f"Message {right}",{"source_analysis":right})
            _edge(edges,f"message:{left}",f"message:{right}","message_similarity",row.similarity_score,_json(row.evidence_json),row.first_observed,row.last_observed)
    truncated=len(nodes)>max_nodes
    node_values=list(nodes.values())[:max_nodes]; allowed={item["id"] for item in node_values}; edge_values=[item for item in edges.values() if item["source"] in allowed and item["target"] in allowed][:max_nodes*2]
    return {"scope":"campaign","scope_id":campaign.id,"nodes":node_values,"edges":edge_values,"truncated":truncated,"limits":{"max_nodes":max_nodes,"max_edges":max_nodes*2}}

def get_campaign_graph(db, campaign_id, max_nodes=500):
    campaign=db.get(ThreatCampaign,campaign_id)
    if not campaign: raise LookupError("campaign not found")
    return _campaign_graph(db,campaign,max_nodes)

def get_incident_graph(db, incident_id, max_nodes=300):
    incident=db.get(SecurityIncident,incident_id)
    if not incident: raise LookupError("incident not found")
    nodes={}; edges={}; _add_incident(db,nodes,edges,incident)
    for relation in db.query(CampaignIncident).filter_by(incident_id=incident.id).all():
        campaign=db.get(ThreatCampaign,relation.campaign_id)
        if campaign:
            _node(nodes,f"campaign:{campaign.id}","campaign",campaign.name,{"status":campaign.status,"confidence":campaign.confidence})
            _edge(edges,f"campaign:{campaign.id}",f"incident:{incident.id}","campaign_membership",relation.confidence or campaign.confidence,{"explanation":relation.explanation},relation.added_at,incident.last_seen,relation.association_status.lower())
    values=list(nodes.values())[:max_nodes]; allowed={x["id"] for x in values}; return {"scope":"incident","scope_id":incident.id,"nodes":values,"edges":[x for x in edges.values() if x["source"] in allowed and x["target"] in allowed][:max_nodes*2],"truncated":len(nodes)>max_nodes,"limits":{"max_nodes":max_nodes,"max_edges":max_nodes*2}}

def campaign_timeline(db, campaign_id):
    campaign=db.get(ThreatCampaign,campaign_id)
    if not campaign: raise LookupError("campaign not found")
    events=[]
    def add(kind, at, title, evidence=None): events.append({"event_type":kind,"timestamp":_iso(at),"title":title,"evidence":evidence or {}})
    add("campaign_discovered",campaign.created_at,campaign.name,{"confidence":campaign.confidence})
    for relation in db.query(CampaignIncident).filter_by(campaign_id=campaign.id).all():
        incident=db.get(SecurityIncident,relation.incident_id)
        if incident:
            add("incident_associated",relation.added_at,f"Incident {incident.id} associated",{"confidence":relation.confidence,"status":relation.association_status})
            for evidence in db.query(IncidentEvidence).filter_by(incident_id=incident.id).all(): add(evidence.evidence_type,evidence.observed_at,"Incident evidence",_json(evidence.details_json))
    for evidence in db.query(CampaignEvidence).filter_by(campaign_id=campaign.id).all(): add(evidence.evidence_type,evidence.observed_at,"Campaign evidence",_json(evidence.details_json))
    for audit in db.query(CampaignAuditEvent).filter_by(campaign_id=campaign.id).all(): add("analyst_action",audit.created_at,audit.action,{"actor":audit.actor,"previous_status":audit.previous_status,"new_status":audit.new_status,"details":_json(audit.details_json)})
    return {"scope":"campaign","scope_id":campaign.id,"events":sorted(events,key=lambda item:item["timestamp"] or "")}

def incident_timeline(db, incident_id):
    incident=db.get(SecurityIncident,incident_id)
    if not incident: raise LookupError("incident not found")
    events=[{"event_type":"incident_discovered","timestamp":_iso(incident.created_at),"title":incident.title,"evidence":{}}]
    for evidence in db.query(IncidentEvidence).filter_by(incident_id=incident.id).all(): events.append({"event_type":evidence.evidence_type,"timestamp":_iso(evidence.observed_at),"title":"Incident evidence","evidence":_json(evidence.details_json)})
    return {"scope":"incident","scope_id":incident.id,"events":sorted(events,key=lambda item:item["timestamp"] or "")}
