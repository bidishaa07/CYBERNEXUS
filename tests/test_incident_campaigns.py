import json
from uuid import uuid4

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.models import MessageAnalysisMetadata, MessageAnalysisRecord, MessageSimilarityResult, SecurityIncident, SecurityIncidentSource, Scan, CorrelationEvidence, ThreatCampaign, CampaignIncident
from backend.app.services.incident_campaigns import group_incidents, list_campaigns, set_campaign_status, reject_campaign_incident
from backend.app.services.investigation_graph import get_campaign_graph, campaign_timeline

def _message(db, token, identifier):
    row = MessageAnalysisRecord(input_sha256=f"{token}-{identifier}", source_type="TEXT", result_json=json.dumps({"indicators": {}})); db.add(row); db.flush()
    db.add(MessageAnalysisMetadata(message_analysis_id=row.id, user_id=token, input_type="TEXT", model_version="test", analysis_status="COMPLETED")); db.flush()
    return row

def test_related_messages_form_reversible_campaign():
    Base.metadata.create_all(bind=engine); db = SessionLocal(); token = str(uuid4())
    try:
        left = _message(db, token, "left"); right = _message(db, token, "right")
        db.add(MessageSimilarityResult(source_message_type="TEXT", source_message_id=str(left.id), related_message_type="TEXT", related_message_id=str(right.id), similarity_score=.88, matching_features_json=json.dumps({"body_similarity": .9}), detection_method="fixture", evidence_json=json.dumps({"explanation": "shared phishing template"}), model_version="test",))
        db.commit(); result = group_incidents(db, threshold=.65)
        left_incident = db.query(SecurityIncidentSource).filter_by(source_type="message", source_id=f"text:{left.id}").one().incident_id
        right_incident = db.query(SecurityIncidentSource).filter_by(source_type="message", source_id=f"text:{right.id}").one().incident_id
        campaigns = [item for item in list_campaigns(db) if left_incident in item["incident_ids"] and right_incident in item["incident_ids"]]
        assert campaigns and campaigns[0]["confidence"] >= .88
        campaign = db.get(ThreatCampaign, campaigns[0]["id"])
        graph = get_campaign_graph(db, campaign.id)
        assert any(node["type"] == "campaign" for node in graph["nodes"])
        assert any(edge["relationship_type"] == "campaign_membership" for edge in graph["edges"])
        timeline = campaign_timeline(db, campaign.id)
        assert timeline["events"] == sorted(timeline["events"], key=lambda item: item["timestamp"] or "")
        set_campaign_status(db, campaign.id, "CONFIRMED", "analyst-1", {"reason": "reviewed evidence"})
        assert db.get(ThreatCampaign, campaign.id).status == "CONFIRMED"
        relation = db.query(CampaignIncident).filter_by(campaign_id=campaign.id, incident_id=left_incident).one()
        reject_campaign_incident(db, campaign.id, left_incident, "analyst-1", "separate after review")
        assert db.get(CampaignIncident, relation.id).association_status == "REJECTED"
    finally:
        db.rollback(); db.close()

def test_single_weak_shared_infrastructure_does_not_create_campaign():
    Base.metadata.create_all(bind=engine); db = SessionLocal(); token = str(uuid4())
    try:
        left = Scan(url=f"https://a-{token}.example", normalized_url="", domain=f"a-{token}.example", result_json="{}"); right = Scan(url=f"https://b-{token}.example", normalized_url="", domain=f"b-{token}.example", result_json="{}"); db.add_all([left, right]); db.flush()
        db.add(CorrelationEvidence(evidence_type="shared_ip", source="fixture", confidence=.35, details_json=json.dumps({"source_scans": [str(left.id), str(right.id)]})))
        db.commit(); group_incidents(db, threshold=.65)
        left_incident = db.query(SecurityIncidentSource).filter_by(source_type="scan", source_id=str(left.id)).one().incident_id
        right_incident = db.query(SecurityIncidentSource).filter_by(source_type="scan", source_id=str(right.id)).one().incident_id
        assert not [item for item in list_campaigns(db) if left_incident in item["incident_ids"] and right_incident in item["incident_ids"]]
    finally:
        db.rollback(); db.close()
