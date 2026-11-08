from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.api import routes


def fake_analysis(text, brands=None, email_providers=None):
    return {
        "classification": "low risk - no confirmed fraud", "score": 4,
        "evidence": [], "indicators": {"urls": [], "emails": [], "phones": []},
        "indicator_intelligence": {"urls": [], "emails": [], "phones": [], "domain_spoofing": []},
        "ml": {"available": True, "prediction": 0, "malicious_probability": 0.04, "model": "fixture-v1"},
        "llm": {"status": "UNAVAILABLE", "available": False},
    }


def test_message_history_persists_reanalysis_and_enforces_owner(monkeypatch):
    monkeypatch.setattr(routes, "analyze_message", fake_analysis)
    client = TestClient(app)
    user = {"X-User-ID": "history-test-user"}
    created = client.post("/api/message-analysis", json={"text": "fixture message"}, headers=user)
    assert created.status_code == 200
    original_id = created.json()["analysis_id"]

    history = client.get("/api/message-analysis/history", headers=user)
    assert history.status_code == 200
    assert any(item["analysis_id"] == original_id for item in history.json()["items"])

    detail = client.get(f"/api/message-analysis/text/{original_id}", headers=user)
    assert detail.status_code == 200
    assert detail.json()["metadata"]["model_version"] == "fixture-v1"

    rerun = client.post(f"/api/message-analysis/text/{original_id}/reanalyze", headers=user)
    assert rerun.status_code == 200
    assert rerun.json()["reanalysis_of"] == original_id
    assert rerun.json()["analysis_id"] != original_id

    denied = client.get(f"/api/message-analysis/text/{original_id}", headers={"X-User-ID": "different-user"})
    assert denied.status_code == 404

    deleted = client.delete(f"/api/message-analysis/text/{original_id}", headers=user)
    assert deleted.status_code == 200
