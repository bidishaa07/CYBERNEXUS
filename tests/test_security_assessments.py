import json
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.main import app
from backend.app.models.models import Scan, SecurityAssessment, SecurityFinding
from backend.app.services.security_assessments import normalize_finding


def _scan():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    token = str(uuid4())
    row = Scan(
        url=f"https://site-{token}.example",
        normalized_url=f"https://site-{token}.example/",
        domain=f"site-{token}.example",
        result_json=json.dumps({"network": {"http": {"headers": {"content-security-policy": "default-src 'self'"}},
            "tls": {"status": "valid"}, "dns": {"status": "available"}, "findings": []}}),
    )
    db.add(row); db.commit(); db.refresh(row)
    return db, row


def test_finding_normalization_preserves_unknown_and_limits_enums():
    result = normalize_finding({"issue": "Provider unavailable", "status": "unavailable", "severity": "invalid", "evidence": {"provider": "x"}}, assessment_id=1, target_url="https://example.com", hostname="example.com")
    assert result["status"] == "UNKNOWN"
    assert result["severity"] == "INFO"
    assert result["check_identifier"] == "provider_unavailable"


def test_assessment_from_scan_persists_normalized_checks_without_duplicates():
    from backend.app.services.security_assessments import create_assessment
    db, scan = _scan()
    row = create_assessment(db, user_id="user:fixture", target_url=scan.url, scan_id=scan.id)
    assert row.finding_count == 7
    assert db.query(SecurityFinding).filter(SecurityFinding.assessment_id == row.id).count() == 7
    assert db.query(SecurityFinding).filter(SecurityFinding.assessment_id == row.id, SecurityFinding.status == "PASS").count() == 3
    db.close()


def test_assessment_api_enforces_owner_and_filters_findings():
    db, scan = _scan(); db.close()
    client = TestClient(app)
    created = client.post("/api/security-assessments", json={"scan_id": scan.id, "target_url": scan.url}, headers={"X-User-ID": "assessment-owner"})
    assert created.status_code == 200
    assessment_id = created.json()["id"]
    assert client.get(f"/api/security-assessments/{assessment_id}", headers={"X-User-ID": "other-user"}).status_code == 403
    details = client.get(f"/api/security-assessments/{assessment_id}", headers={"X-User-ID": "assessment-owner"})
    assert details.status_code == 200
    assert details.json()["findings"]
    filtered = client.get(f"/api/security-assessments/{assessment_id}/findings?category=TLS", headers={"X-User-ID": "assessment-owner"})
    assert filtered.status_code == 200
    assert all(item["category"] == "TLS" for item in filtered.json()["items"])
