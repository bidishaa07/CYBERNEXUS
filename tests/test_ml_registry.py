from pathlib import Path
import json
import uuid
import time

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.config import settings
from backend.app.services import ml_registry
from backend.app.services import ml_training
from backend.app.db.session import SessionLocal
from backend.app.models.models import MLDatasetVersion


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

def test_manual_retraining_creates_unapproved_candidate_without_replacing_production(tmp_path, monkeypatch):
    dataset_root = tmp_path / "dataset"; dataset_root.mkdir()
    rows=["body,label"] + [f"legitimate notice {i},0" for i in range(10)] + [f"urgent password request {i},1" for i in range(10)]
    path=dataset_root / "fixture.csv"; path.write_text("\n".join(rows)+"\n",encoding="utf-8")
    monkeypatch.setattr(ml_registry, "DATASET_ROOT", dataset_root.resolve()); monkeypatch.setattr(ml_training, "DATASET_ROOT", dataset_root.resolve())
    quality=ml_registry.validate_dataset("fixture.csv")
    db=SessionLocal(); dataset=MLDatasetVersion(dataset_id="phase7-fixture-"+uuid.uuid4().hex[:8],version="v1",source="fixture.csv",checksum=quality["checksum"],record_count=quality["record_count"],class_distribution_json="{}",quality_json=json.dumps(quality["quality"]),preprocessing_version="fixture-v1",validation_status="VALID",approval_status="APPROVED",created_by="test"); db.add(dataset); db.commit(); db.refresh(dataset); dataset_id=dataset.id; db.close()
    client=TestClient(app); response=client.post("/api/ml/retraining",json={"dataset_version_id":dataset_id},headers={"X-Admin-Token":settings.admin_api_token})
    assert response.status_code == 200
    status=None
    for _ in range(40):
        status=client.get("/api/ml/training/"+str(response.json()["training_run_id"]),headers={"X-Admin-Token":settings.admin_api_token})
        if status.json().get("status") not in {"PENDING","RUNNING"}: break
        time.sleep(.25)
    assert status is not None and status.status_code == 200
    assert status.json()["status"] in {"COMPLETED","EVALUATION_FAILED"}
