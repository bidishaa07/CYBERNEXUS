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
        url=f"https://report-{token}.example",
        normalized_url=f"https://report-{token}.example/",
        domain=f"report-{token}.example",
        result_json=json.dumps({
            "network": {
                "http": {"headers": {}},
                "tls": {"status": "unavailable"},
                "dns": {"status": "available"},
                "findings": [{"category": "HSTS", "check_identifier": "unsafe,value", "title": "Unsafe, header", "status": "FAIL", "severity": "HIGH", "confidence": "HIGH", "evidence": {"value": "a, b"}, "limitation": "Controlled test evidence"}],
            }
        }),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    db.close()
    return scan


def test_security_assessment_exports_and_history_are_persisted():
    scan = make_scan()
    client = TestClient(app)
    owner = {"X-User-ID": "report-owner"}
    created = client.post("/api/security-assessments", json={"scan_id": scan.id, "target_url": scan.url}, headers=owner)
    assert created.status_code == 200
    assessment_id = created.json()["id"]

    report = client.get(f"/api/security-assessments/{assessment_id}/report?format=json", headers=owner)
    assert report.status_code == 200
    body = report.json()
    assert body["report_version"] == "1.0"
    assert body["executive_summary"]["assessment_id"] == assessment_id
    assert body["executive_summary"]["total_checks"] == len(body["findings"])
    hsts = next(item for item in body["findings"] if item["title"] == "Unsafe, header")
    assert hsts["evidence"]["value"] == "a, b"
    assert body["category_analysis"]["OTHER"]["finding_count"] >= 1

    csv_report = client.get(f"/api/security-assessments/{assessment_id}/report?format=csv", headers=owner)
    assert csv_report.status_code == 200
    assert "Unsafe, header" in csv_report.text
    assert '"a, b"' in csv_report.text

    pdf_report = client.get(f"/api/security-assessments/{assessment_id}/report?format=pdf", headers=owner)
    assert pdf_report.status_code == 200
    assert pdf_report.content.startswith(b"%PDF")

    history = client.get(f"/api/security-assessments/{assessment_id}/reports", headers=owner)
    assert history.status_code == 200
    assert len(history.json()["items"]) == 3
    assert {item["format"] for item in history.json()["items"]} == {"json", "csv", "pdf"}


def test_security_assessment_report_authorization_and_invalid_format():
    scan = make_scan()
    client = TestClient(app)
    owner = {"X-User-ID": "report-owner-a"}
    created = client.post("/api/security-assessments", json={"scan_id": scan.id, "target_url": scan.url}, headers=owner)
    assessment_id = created.json()["id"]
    assert client.get(f"/api/security-assessments/{assessment_id}/report?format=xml", headers=owner).status_code == 400
    assert client.get(f"/api/security-assessments/{assessment_id}/report?format=json", headers={"X-User-ID": "report-owner-b"}).status_code == 403
    assert client.get(f"/api/security-assessments/{assessment_id}/reports", headers={"X-User-ID": "report-owner-b"}).status_code == 403
