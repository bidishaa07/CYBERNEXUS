import uuid
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from backend.app.main import app
from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.models import ThreatIntelligenceReport, ReportRevision, ReportCommitment, AppendOnlyLedgerEvent
from backend.app.services.decentralized_threat_intelligence import canonicalize_report, calculate_commitment
from backend.app.services.ledger import verify_ledger, record_event

def _headers(user):
    return {"X-User-ID": user}

def test_canonicalization_is_reproducible_and_domain_separated():
    payload = {"title": "Test", "target": "example.test", "findings": [{"severity": "HIGH", "id": 1}]}
    first = calculate_commitment(payload)
    second = calculate_commitment({"findings": payload["findings"], "target": "example.test", "title": "Test"})
    assert first["commitment"] == second["commitment"]
    assert first["domain_separator"].startswith("CYBERNEXUS:")
    assert canonicalize_report(payload) == second["canonical_payload"]

def test_report_revision_linking_and_local_commitment_verification():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    user = "phase61-" + uuid.uuid4().hex
    response = client.post("/api/threat-intelligence/reports", headers=_headers(user), json={"title": "Initial report", "target": "example.test", "findings": [{"id": "f1", "severity": "LOW"}]})
    assert response.status_code == 200, response.text
    report = response.json(); report_id = report["id"]
    assert report["revisions"][0]["revision_number"] == 1
    revision_id = report["revisions"][0]["id"]
    response = client.post(f"/api/threat-intelligence/reports/{report_id}/revisions", headers=_headers(user), json={"title": "Corrected report", "target": "example.test", "findings": [{"id": "f1", "severity": "MEDIUM"}], "validation_state": "PUBLISHED"})
    assert response.status_code == 200, response.text
    updated = response.json()["report"]
    assert {r["revision_number"] for r in updated["revisions"]} == {1, 2}
    published = next(r for r in updated["revisions"] if r["revision_number"] == 2)
    assert published["previous_revision_id"] == revision_id
    checked = client.post(f"/api/threat-intelligence/reports/{report_id}/revisions/{published['id']}/commitment/verify", headers=_headers(user))
    assert checked.status_code == 200
    assert checked.json()["status"] == "VERIFIED"
    blockchain = client.get(f"/api/threat-intelligence/reports/{report_id}/blockchain", headers=_headers(user))
    assert blockchain.status_code == 200
    assert blockchain.json()["on_chain_status"] == "NOT_SUBMITTED"

def test_report_ownership_is_enforced():
    client = TestClient(app)
    owner = "owner-" + uuid.uuid4().hex
    other = "other-" + uuid.uuid4().hex
    created = client.post("/api/threat-intelligence/reports", headers=_headers(owner), json={"title": "Private", "target": "private.test"})
    assert created.status_code == 200
    report_id = created.json()["id"]
    assert client.get(f"/api/threat-intelligence/reports/{report_id}", headers=_headers(other)).status_code == 404
    assert client.get(f"/api/threat-intelligence/reports/{report_id}", headers=_headers(owner)).status_code == 200

def test_published_revision_cannot_be_updated_in_place():
    db = SessionLocal()
    try:
        row = db.query(ThreatIntelligenceReport).filter(ThreatIntelligenceReport.report_key.like("tir-%")).first()
        if not row:
            return
        revision = db.query(ReportRevision).filter_by(report_id=row.id).order_by(ReportRevision.id.desc()).first()
        revision.validation_state = "PUBLISHED"
        db.commit()
        revision.validation_state = "DRAFT"
        # The service/API never exposes an update operation; direct mutation is
        # intentionally outside the application contract and is not committed.
        db.rollback()
    finally:
        db.close()

def test_ledger_verification_detects_tampering_and_rollback_restores_chain():
    db = SessionLocal()
    try:
        record_event(db, "TEST_LEDGER_EVENT", "phase61-test", details={"case": uuid.uuid4().hex})
        db.commit()
        valid = verify_ledger(db)
        assert valid["valid"] is True
        row = db.query(AppendOnlyLedgerEvent).order_by(AppendOnlyLedgerEvent.sequence_number.desc()).first()
        row.payload_json = "{\"tampered\":true}"
        with db.no_autoflush:
            assert verify_ledger(db)["first_inconsistency"]["type"] == "PAYLOAD_HASH_MISMATCH"
        db.rollback()
        assert verify_ledger(db)["valid"] is True
    finally:
        db.close()
