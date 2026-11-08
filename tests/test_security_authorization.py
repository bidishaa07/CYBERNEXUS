from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app


def authorization_payload(**overrides):
    value = {
        "target_hostname": "example.com",
        "authorized_organization": "Example Organization",
        "authorization_confirmation": True,
        "permitted_scope": ["example.com", "www.example.com"],
        "allowed_categories": ["TLS", "REDIRECTS"],
        "start_time": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "expiration_time": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "supporting_reference": "ticket-123",
    }
    value.update(overrides)
    return value


def test_authorization_requires_confirmation_and_admin_approval():
    client = TestClient(app)
    owner = {"X-User-ID": "authorized-requester"}
    missing_confirmation = client.post("/api/security-authorizations", json=authorization_payload(authorization_confirmation=False), headers=owner)
    assert missing_confirmation.status_code == 400
    created = client.post("/api/security-authorizations", json=authorization_payload(), headers=owner)
    assert created.status_code == 200
    record = created.json()
    assert record["approval_status"] == "PENDING"
    assert record["authorization_confirmed"] is True
    assert record["history"][0]["action"] == "CREATED"

    approved = client.post(f"/api/security-authorizations/{record['id']}/approve", headers={"X-User-ID": "administrator", "X-Admin-Token": settings.admin_api_token})
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "APPROVED"

    active = client.post("/api/security-assessments", json={"target_url": "https://www.example.com/", "assessment_mode": "ACTIVE", "authorization_id": record["id"], "allowed_categories": ["TLS"]}, headers=owner)
    assert active.status_code == 200
    assert active.json()["assessment_mode"] == "ACTIVE"
    assert active.json()["authorization_id"] == record["id"]


def test_active_assessment_rejects_missing_or_out_of_scope_authorization():
    client = TestClient(app)
    owner = {"X-User-ID": "active-requester"}
    missing = client.post("/api/security-assessments", json={"target_url": "https://example.com/", "assessment_mode": "ACTIVE"}, headers=owner)
    assert missing.status_code == 403

    created = client.post("/api/security-authorizations", json=authorization_payload(target_hostname="approved.example", permitted_scope=["approved.example"]), headers=owner)
    assert created.status_code == 200
    approved = client.post(f"/api/security-authorizations/{created.json()['id']}/approve", headers={"X-User-ID": "administrator", "X-Admin-Token": settings.admin_api_token})
    assert approved.status_code == 200
    outside = client.post("/api/security-assessments", json={"target_url": "https://other.example/", "assessment_mode": "ACTIVE", "authorization_id": created.json()["id"], "allowed_categories": ["TLS"]}, headers=owner)
    assert outside.status_code == 403


def test_authorization_revoke_is_audited_and_blocks_active_assessment():
    client = TestClient(app)
    owner = {"X-User-ID": "revocation-requester"}
    created = client.post("/api/security-authorizations", json=authorization_payload(), headers=owner).json()
    assert client.post(f"/api/security-authorizations/{created['id']}/approve", headers={"X-User-ID": "administrator", "X-Admin-Token": settings.admin_api_token}).status_code == 200
    revoked = client.post(f"/api/security-authorizations/{created['id']}/revoke", headers={"X-User-ID": "administrator", "X-Admin-Token": settings.admin_api_token})
    assert revoked.status_code == 200
    body = revoked.json()
    assert body["approval_status"] == "REVOKED"
    assert any(item["action"] == "REVOKED" for item in body["history"])
    blocked = client.post("/api/security-assessments", json={"target_url": "https://example.com/", "assessment_mode": "ACTIVE", "authorization_id": created["id"], "allowed_categories": ["TLS"]}, headers=owner)
    assert blocked.status_code == 403
