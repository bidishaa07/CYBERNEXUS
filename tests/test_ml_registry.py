from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.services import ml_registry


def test_dataset_validation_tracks_duplicates_and_invalid_labels(tmp_path, monkeypatch):
    dataset_root = tmp_path / "dataset"; dataset_root.mkdir()
    (dataset_root / "fixture.csv").write_text("body,label\nalpha,0\nalpha,1\nbeta,2\n,0\n", encoding="utf-8")
    monkeypatch.setattr(ml_registry, "DATASET_ROOT", dataset_root.resolve())
    result = ml_registry.validate_dataset("fixture.csv")
    assert result["validation_status"] == "INVALID"
    assert result["quality"]["duplicate_records"] == 1
    assert result["quality"]["inconsistent_duplicate_labels"] == 1
    assert result["quality"]["empty_content"] == 1


def test_model_registry_endpoint_is_admin_protected_and_reports_active_model():
    client = TestClient(app)
    assert client.get("/api/ml/registry").status_code == 403
    response = client.get("/api/ml/registry", headers={"X-Admin-Token": settings.admin_api_token})
    assert response.status_code == 200
    assert response.json()["production"]["available"] is True
    assert response.json()["production"]["model_version"]
