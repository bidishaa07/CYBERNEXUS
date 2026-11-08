import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.db.session import Base, SessionLocal, engine
from backend.app.main import app
from backend.app.models.models import EvidenceObject, ProvenanceEvent
from backend.app.services.evidence_storage import cleanup_expired


def _headers(user):
    return {"X-User-ID": user}


def _report(client, user):
    response = client.post(
        "/api/threat-intelligence/reports",
        headers=_headers(user),
        json={"title": "Evidence fixture", "target": "example.test", "findings": []},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["id"], body["revisions"][0]["id"]


def test_evidence_upload_retrieval_manifest_and_integrity(monkeypatch, tmp_path):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "evidence_storage_root", str(tmp_path))
    client = TestClient(app)
    user = "evidence-owner-" + uuid.uuid4().hex
    report_id, revision_id = _report(client, user)
    payload = b'{"source":"controlled-fixture","value":1}'

    uploaded = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence",
        headers=_headers(user),
        params={"reference_type": "SCAN_RESULT", "description": "fixture result"},
        files={"file": ("result.json", payload, "application/json")},
    )
    assert uploaded.status_code == 200, uploaded.text
    body = uploaded.json()
    evidence_id = body["evidence"]["id"]
    assert body["evidence"]["object_hash"] == hashlib.sha256(payload).hexdigest()
    assert body["evidence"]["encryption_status"].startswith("FERNET")
    assert body["evidence"]["integrity"]["status"] == "VERIFIED"
    assert body["manifest"]["manifest_hash"]

    metadata = client.get(f"/api/threat-intelligence/evidence/{evidence_id}", headers=_headers(user))
    assert metadata.status_code == 200
    assert metadata.json()["integrity"]["status"] == "VERIFIED"
    content = client.get(f"/api/threat-intelligence/evidence/{evidence_id}/content", headers=_headers(user))
    assert content.status_code == 200
    assert content.content == payload

    manifest = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence/manifests/verify",
        headers=_headers(user),
    )
    assert manifest.status_code == 200
    assert manifest.json()["status"] == "VERIFIED"

    provenance = client.get(f"/api/threat-intelligence/reports/{report_id}/provenance", headers=_headers(user))
    assert provenance.status_code == 200
    events = provenance.json()["items"]
    assert any(item["event_type"] == "EVIDENCE_ADDED" and item["ledger_event_id"] for item in events)


def test_evidence_tampering_is_detected_and_other_users_are_denied(monkeypatch, tmp_path):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "evidence_storage_root", str(tmp_path))
    client = TestClient(app)
    owner = "evidence-owner-" + uuid.uuid4().hex
    other = "evidence-other-" + uuid.uuid4().hex
    report_id, revision_id = _report(client, owner)
    uploaded = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence",
        headers=_headers(owner),
        files={"file": ("notes.txt", b"original", "text/plain")},
    )
    assert uploaded.status_code == 200, uploaded.text
    evidence_id = uploaded.json()["evidence"]["id"]

    denied = client.get(f"/api/threat-intelligence/evidence/{evidence_id}", headers=_headers(other))
    assert denied.status_code == 403

    db = SessionLocal()
    try:
        row = db.get(EvidenceObject, evidence_id)
        (tmp_path / row.storage_uri).write_bytes(b"modified")
    finally:
        db.close()

    checked = client.post(f"/api/threat-intelligence/evidence/{evidence_id}/verify", headers=_headers(owner))
    assert checked.status_code == 200
    assert checked.json()["status"] == "HASH_MISMATCH"
    download = client.get(f"/api/threat-intelligence/evidence/{evidence_id}/content", headers=_headers(owner))
    assert download.status_code == 409


def test_evidence_rejects_invalid_json_and_oversized_content(monkeypatch, tmp_path):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "evidence_storage_root", str(tmp_path))
    monkeypatch.setattr(settings, "evidence_max_bytes", 4)
    client = TestClient(app)
    user = "evidence-validation-" + uuid.uuid4().hex
    report_id, revision_id = _report(client, user)

    invalid_json = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence",
        headers=_headers(user),
        files={"file": ("bad.json", b"bad", "application/json")},
    )
    assert invalid_json.status_code == 400

    oversized = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence",
        headers=_headers(user),
        files={"file": ("large.txt", b"12345", "text/plain")},
    )
    assert oversized.status_code == 400


def test_ipfs_unavailable_and_retention_cleanup_are_explicit(monkeypatch, tmp_path):
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "evidence_storage_root", str(tmp_path))
    monkeypatch.setattr(settings, "evidence_ipfs_pin_url", "")
    client = TestClient(app)
    user = "evidence-retention-" + uuid.uuid4().hex
    report_id, revision_id = _report(client, user)
    uploaded = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/evidence",
        headers=_headers(user),
        files={"file": ("retention.txt", b"retained", "text/plain")},
    )
    assert uploaded.status_code == 200, uploaded.text
    evidence_id = uploaded.json()["evidence"]["id"]
    assert client.post(f"/api/threat-intelligence/evidence/{evidence_id}/ipfs", headers=_headers(user)).json()["status"] == "UNAVAILABLE"

    db = SessionLocal()
    try:
        row = db.get(EvidenceObject, evidence_id)
        row.retention_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.commit()
        result = cleanup_expired(db, "retention-test")
        assert evidence_id in result["evidence_ids"]
        assert db.get(EvidenceObject, evidence_id).status == "DELETED"
    finally:
        db.close()

