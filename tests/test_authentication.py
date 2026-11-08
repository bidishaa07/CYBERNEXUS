from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api import routes
from backend.app.services import auth


def fake_analysis(text, brands=None, email_providers=None):
    return {"classification": "low risk", "score": 1, "evidence": [], "indicators": {"urls": [], "emails": [], "phones": []}, "indicator_intelligence": {"urls": [], "emails": [], "phones": [], "domain_spoofing": []}, "ml": {"available": True, "prediction": 0, "malicious_probability": 0.01, "model": "auth-fixture"}, "llm": {"status": "UNAVAILABLE", "available": False}}


def test_missing_authentication_is_rejected_when_required(monkeypatch):
    monkeypatch.setattr(auth.settings, "auth_required", True)
    response = TestClient(app).get("/api/message-analysis/history")
    assert response.status_code == 401


def test_verified_oidc_subject_controls_history_ownership(monkeypatch):
    monkeypatch.setattr(auth.settings, "auth_required", True)
    monkeypatch.setattr(routes, "analyze_message", fake_analysis)
    monkeypatch.setattr(auth, "verify_token", lambda token: {"sub": token, "email": f"{token}@example.test", "name": token, "roles": []})
    client = TestClient(app)
    alice = {"Authorization": "Bearer oidc-alice"}; bob = {"Authorization": "Bearer oidc-bob"}
    created = client.post("/api/message-analysis", json={"text": "private alice message"}, headers=alice)
    assert created.status_code == 200
    analysis_id = created.json()["analysis_id"]
    assert client.get("/api/message-analysis/history", headers=alice).json()["total"] >= 1
    assert client.get("/api/message-analysis/text/%s" % analysis_id, headers=bob).status_code == 404
    assert client.get("/api/message-analysis/text/%s" % analysis_id, headers=alice).status_code == 200
