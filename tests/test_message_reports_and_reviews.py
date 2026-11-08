import json

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api import routes
from backend.app.core.config import settings


def fixture_analysis(text, brands=None, email_providers=None):
    return {
        "classification": "high risk - not confirmed fraud",
        "score": 82,
        "evidence": [{"type": "urgency", "severity": "high", "explanation": "Fixture evidence"}],
        "indicators": {"urls": [], "emails": [], "phones": []},
        "indicator_intelligence": {"urls": [], "emails": [], "phones": [], "domain_spoofing": []},
        "ml": {"available": True, "prediction": 1, "malicious_probability": 0.82, "model": "phase5-fixture"},
        "llm": {"status": "UNAVAILABLE", "available": False},
    }


def test_persisted_report_exports_and_invalid_format(monkeypatch):
    monkeypatch.setattr(routes, "analyze_message", fixture_analysis)
    client = TestClient(app)
    headers = {"X-User-ID": "phase5-report-user"}
    created = client.post("/api/message-analysis", json={"text": "phase5 report fixture"}, headers=headers)
    assert created.status_code == 200
    analysis_id = created.json()["analysis_id"]

    report = client.get(f"/api/message-analysis/reports/text/{analysis_id}?format=json", headers=headers)
    assert report.status_code == 200
    assert report.json()["automated_assessment"]["risk_score"] == 82
    assert report.json()["metadata"]["model_version"] == "phase5-fixture"
    assert client.get(f"/api/message-analysis/reports/text/{analysis_id}?format=csv", headers=headers).headers["content-type"].startswith("text/csv")
    assert client.get(f"/api/message-analysis/reports/text/{analysis_id}?format=pdf", headers=headers).content.startswith(b"%PDF")
    assert client.get(f"/api/message-analysis/reports/text/{analysis_id}?format=xml", headers=headers).status_code == 400
    assert client.get(f"/api/message-analysis/reports/text/{analysis_id}?format=json", headers={"X-User-ID": "other-user"}).status_code == 404


def test_admin_review_workflow_audit_and_feedback(monkeypatch):
    monkeypatch.setattr(routes, "analyze_message", fixture_analysis)
    client = TestClient(app)
    created = client.post("/api/message-analysis", json={"text": "phase5 review fixture"}, headers={"X-User-ID": "review-owner"})
    analysis_id = created.json()["analysis_id"]
    admin = {"X-Admin-Token": settings.admin_api_token}
    listing = client.get("/api/admin/message-reviews", headers=admin)
    assert listing.status_code == 200
    review = next(item for item in listing.json()["items"] if item["analysis_id"] == analysis_id)
    review_id = review["review_id"]
    changed = client.post(f"/api/admin/message-reviews/{review_id}/status", json={"status": "UNDER_REVIEW", "reason": "Analyst triage"}, headers=admin)
    assert changed.status_code == 200
    feedback = client.post(f"/api/admin/message-reviews/{review_id}/feedback", json={"label": "MALICIOUS", "certainty": "MEDIUM", "evidence": "Needs dataset validation"}, headers=admin)
    assert feedback.json()["approval_status"] == "PENDING_VALIDATION"
    detail = client.get(f"/api/admin/message-reviews/{review_id}", headers=admin)
    assert detail.status_code == 200
    assert detail.json()["review"]["status"] == "UNDER_REVIEW"
    assert detail.json()["audit"]
    assert detail.json()["feedback"][0]["approval_status"] == "PENDING_VALIDATION"

