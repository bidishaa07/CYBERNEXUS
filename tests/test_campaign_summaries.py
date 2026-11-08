import json
from uuid import uuid4

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.models import CampaignEvidence, ThreatCampaign
from backend.app.services import campaign_summaries

def _campaign(db, token):
    row=ThreatCampaign(campaign_key=f"summary-test:{token}",name="Evidence campaign",description="test",severity="MEDIUM",confidence=.72,status="NEW")
    db.add(row); db.commit(); db.refresh(row); return row

def test_deterministic_summary_preserves_evidence_refs_when_llm_unavailable(monkeypatch):
    Base.metadata.create_all(bind=engine); db=SessionLocal(); token=str(uuid4())
    try:
        row=_campaign(db,token)
        db.add(CampaignEvidence(campaign_id=row.id,evidence_type="shared_certificate",source="fixture",confidence=.92,details_json=json.dumps({"certificate_fingerprint":"ab"*32}))); db.commit()
        monkeypatch.setattr(campaign_summaries, "explain_campaign", lambda evidence, correlation_id: {"available":False,"status":"UNAVAILABLE","reason":"test provider unavailable"})
        result=campaign_summaries.generate_campaign_summary(db,row.id)
        assert result["generation_status"] == "DETERMINISTIC_FALLBACK"
        assert result["provider"] == "none"
        assert "shared_certificate" in result["summary_text"]
        assert result["evidence_refs"]
        assert campaign_summaries.summary_history(db,row.id)[0]["id"] == result["id"]
    finally: db.rollback(); db.close()

def test_llm_receives_persisted_evidence_without_raw_message_content(monkeypatch):
    Base.metadata.create_all(bind=engine); db=SessionLocal(); token=str(uuid4())
    try:
        row=_campaign(db,token); db.add(CampaignEvidence(campaign_id=row.id,evidence_type="message_similarity",source="fixture",confidence=.8,details_json=json.dumps({"source_analyses":["text:1"],"explanation":"shared template"}))); db.commit()
        captured={}
        def fake(evidence, correlation_id): captured.update(evidence); return {"available":True,"status":"CONNECTED","provider":"test","model":"test-model","explanation":"Evidence-grounded summary"}
        monkeypatch.setattr(campaign_summaries, "explain_campaign", fake)
        result=campaign_summaries.generate_campaign_summary(db,row.id)
        assert result["generation_status"] == "LLM_GENERATED"
        assert captured["evidence"][0]["type"] == "message_similarity"
        serialized = json.dumps(captured, default=str).lower()
        assert "untrusted evidence json" not in serialized
        assert "password" not in serialized
    finally: db.rollback(); db.close()
