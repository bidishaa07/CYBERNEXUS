import json
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.main import app
from backend.app.models.models import Scan


def make_scan():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    token = uuid4().hex
    scan = Scan(
        url=f"https://findings-{token}.example",
        normalized_url=f"https://findings-{token}.example/",
        domain=f"findings-{token}.example",
        result_json=json.dumps({
            "network": {
                "http": {"headers": {"content-security-policy": "default-src 'self'"}},
                "tls": {"status": "valid"},
                "dns": {"status": "available"},
                "findings": [],
            }
        }),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.close()
    return scan


def test_finding_search_filters_and_remediation_verification_workflow():
    scan = make_scan()
    client = TestClient(app)
    headers = {"X-User-ID": "finding-owner"}

    assessment = client.post(
        "/api/security-assessments",
        json={"scan_id": scan.id, "target_url": scan.url},
        headers=headers,
    )
    assert assessment.status_code == 200
    assessment_id = assessment.json()["id"]

    response = client.get(
        "/api/security-findings",
        params={"assessment_id": assessment_id, "category": "TLS", "status": "PASS", "page_size": 2},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["total"] >= 1
    assert all(item["category"] == "TLS" for item in response.json()["items"])
    assert response.json()["counts"]["remediation"]["OPEN"] >= 1

    finding_id = response.json()["items"][0]["id"]
    acknowledged = client.patch(
        f"/api/security-findings/{finding_id}/remediation",
        json={"status": "ACKNOWLEDGED", "note": "Reviewer acknowledged the finding"},
        headers=headers,
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["remediation"]["status"] == "ACKNOWLEDGED"

    fixed_without_verification = client.patch(
        f"/api/security-findings/{finding_id}/remediation",
        json={"status": "FIXED"},
        headers=headers,
    )
    assert fixed_without_verification.status_code == 409

    verified = client.post(
        f"/api/security-findings/{finding_id}/verify",
        json={"verified": True, "note": "Technical recheck passed"},
        headers=headers,
    )
    assert verified.status_code == 200
    assert verified.json()["remediation"]["status"] == "FIXED"
    assert verified.json()["remediation"]["verification_status"] == "VERIFIED"
    assert any(event["action"] == "VERIFIED" for event in verified.json()["remediation"]["history"])


def test_finding_management_enforces_ownership():
    scan = make_scan()
    client = TestClient(app)
    owner = {"X-User-ID": "finding-owner-a"}
    created = client.post(
        "/api/security-assessments",
        json={"scan_id": scan.id, "target_url": scan.url},
        headers=owner,
    )
    assert created.status_code == 200
    assessment_id = created.json()["id"]

    denied = client.get(
        "/api/security-findings",
        params={"assessment_id": assessment_id},
        headers={"X-User-ID": "finding-owner-b"},
    )
    assert denied.status_code == 200
    assert denied.json()["total"] == 0

    finding_id = created.json()["findings"][0]["id"]
    denied_update = client.patch(
        f"/api/security-findings/{finding_id}/remediation",
        json={"status": "ACKNOWLEDGED"},
        headers={"X-User-ID": "finding-owner-b"},
    )
    assert denied_update.status_code == 403
