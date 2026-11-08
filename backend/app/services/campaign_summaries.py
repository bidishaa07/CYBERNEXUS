"""Evidence-grounded campaign summaries with deterministic fallback."""
import json
from datetime import datetime, timezone

from backend.app.models.models import CampaignEvidence, CampaignIncident, CampaignSummary, IncidentIndicator, SecurityIncident, SecurityIncidentSource, ThreatCampaign, ThreatIndicator
from backend.app.services.llm import explain_campaign

def _now(): return datetime.now(timezone.utc)
def _json(value):
    try: return json.loads(value or "{}")
    except (TypeError, ValueError): return {}

def evidence_bundle(db, campaign):
    incident_ids=[row.incident_id for row in db.query(CampaignIncident).filter_by(campaign_id=campaign.id, association_status="ACTIVE").all()]
    incidents=[]; source_refs=[]; indicator_refs=[]
    for incident_id in incident_ids:
        incident=db.get(SecurityIncident,incident_id)
        if not incident: continue
        sources=[{"source_type":row.source_type,"source_id":row.source_id} for row in db.query(SecurityIncidentSource).filter_by(incident_id=incident.id).all()]
        indicators=[]
        for link in db.query(IncidentIndicator).filter_by(incident_id=incident.id).all():
            indicator=db.get(ThreatIndicator,link.indicator_id)
            if indicator:
                indicators.append({"indicator_id":indicator.id,"type":indicator.indicator_type,"normalized_value":indicator.indicator,"verification_status":indicator.verification_status,"source":indicator.source})
                indicator_refs.append({"indicator_id":indicator.id,"type":indicator.indicator_type})
        incidents.append({"incident_id":incident.id,"status":incident.status,"severity":incident.severity,"title":incident.title,"first_seen":incident.first_seen,"last_seen":incident.last_seen,"sources":sources,"indicators":indicators})
        source_refs.extend({"kind":"analysis","source_type":item["source_type"],"source_id":item["source_id"]} for item in sources)
    evidence=[{"evidence_id":row.id,"type":row.evidence_type,"source":row.source,"confidence":row.confidence,"details":_json(row.details_json),"observed_at":row.observed_at} for row in db.query(CampaignEvidence).filter_by(campaign_id=campaign.id).all()]
    source_refs.extend({"kind":"campaign_evidence","evidence_id":item["evidence_id"]} for item in evidence)
    return {"campaign":{"campaign_id":campaign.id,"campaign_key":campaign.campaign_key,"status":campaign.status,"severity":campaign.severity,"confidence":campaign.confidence,"first_seen":campaign.first_seen,"last_seen":campaign.last_seen},"incidents":incidents,"evidence":evidence,"indicator_refs":indicator_refs,"source_refs":source_refs,"limitations":["Raw message bodies and secrets are excluded from the model context.","Correlation evidence does not prove ownership, attribution or malicious intent.","Unavailable provider results remain unknown."]}

def deterministic_summary(bundle):
    campaign=bundle["campaign"]; incidents=bundle["incidents"]; evidence=bundle["evidence"]; indicators=bundle["indicator_refs"]
    types=sorted({item["type"] for item in indicators}); relationships=sorted({item["type"] for item in evidence})
    return (f"Campaign {campaign['campaign_id']} has {len(incidents)} associated incident(s) with stored correlation confidence {round((campaign.get('confidence') or 0)*100)}%. "
            f"Observed evidence types: {', '.join(relationships) or 'none'}. Related indicator types: {', '.join(types) or 'none'}. "
            "The evidence supports a possible relationship between these records, but does not establish a threat actor, ownership, geography, victim set or malicious intent. "
            "Review the linked source analyses and provider results; missing intelligence remains unknown.")

def generate_campaign_summary(db, campaign_id):
    campaign=db.get(ThreatCampaign,campaign_id)
    if not campaign: raise LookupError("campaign not found")
    bundle=evidence_bundle(db,campaign)
    result=explain_campaign(bundle, f"campaign-{campaign.id}-{int(_now().timestamp())}")
    if result.get("available"):
        text=result.get("explanation") or deterministic_summary(bundle); status="LLM_GENERATED"; provider=result.get("provider") or "unknown"; model=result.get("model")
    else:
        text=deterministic_summary(bundle); status="DETERMINISTIC_FALLBACK"; provider="none"; model=None
    version=f"{campaign.id}:{campaign.updated_at.isoformat() if campaign.updated_at else 'unknown'}"
    row=CampaignSummary(campaign_id=campaign.id,campaign_version=version,summary_text=text,evidence_refs_json=json.dumps(bundle["source_refs"],default=str),provider=provider,model=model,generation_status=status,generated_at=_now())
    db.add(row); db.commit(); db.refresh(row)
    return {"id":row.id,"campaign_id":row.campaign_id,"campaign_version":row.campaign_version,"summary_text":row.summary_text,"evidence_refs":bundle["source_refs"],"provider":row.provider,"model":row.model,"generation_status":row.generation_status,"generated_at":row.generated_at,"llm_status":result.get("status"),"llm_reason":result.get("reason")}

def summary_history(db,campaign_id):
    return [{"id":row.id,"campaign_id":row.campaign_id,"campaign_version":row.campaign_version,"summary_text":row.summary_text,"evidence_refs":_json(row.evidence_refs_json) if row.evidence_refs_json else [],"provider":row.provider,"model":row.model,"generation_status":row.generation_status,"generated_at":row.generated_at} for row in db.query(CampaignSummary).filter_by(campaign_id=campaign_id).order_by(CampaignSummary.generated_at.desc()).all()]
