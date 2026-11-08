import uuid

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.db.session import Base, engine
from backend.app.main import app


def _headers(user: str):
    return {"X-User-ID": user}


def _create_report(client, user: str):
    response = client.post(
        "/api/threat-intelligence/reports",
        headers=_headers(user),
        json={"title": "Wallet signature fixture", "target": "example.test", "findings": []},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["id"], body["revisions"][0]["id"]


def test_wallet_ownership_challenge_requires_valid_signature_and_cannot_replay():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    user = "wallet-owner-" + uuid.uuid4().hex
    account = Account.create()

    challenge_response = client.post(
        "/api/threat-intelligence/wallet/challenges",
        headers=_headers(user),
        json={"address": account.address, "action": "WALLET_OWNERSHIP"},
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()
    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]), private_key=account.key
    )

    verified = client.post(
        f"/api/threat-intelligence/wallet/challenges/{challenge['challenge_id']}/verify",
        headers=_headers(user),
        json={
            "address": account.address,
            "signature": signed.signature.hex(),
            "chain_id": settings.blockchain_chain_id or 11155111,
        },
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["verified"] is True

    replay = client.post(
        f"/api/threat-intelligence/wallet/challenges/{challenge['challenge_id']}/verify",
        headers=_headers(user),
        json={
            "address": account.address,
            "signature": signed.signature.hex(),
            "chain_id": settings.blockchain_chain_id or 11155111,
        },
    )
    assert replay.status_code == 400
    assert "consumed" in replay.json()["detail"]


def test_wallet_ownership_rejects_signature_from_the_wrong_wallet():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    user = "wallet-wrong-signer-" + uuid.uuid4().hex
    challenged = Account.create()
    wrong_signer = Account.create()
    challenge_response = client.post(
        "/api/threat-intelligence/wallet/challenges",
        headers=_headers(user),
        json={"address": challenged.address},
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()
    signed = Account.sign_message(
        encode_defunct(text=challenge["message"]), private_key=wrong_signer.key
    )
    rejected = client.post(
        f"/api/threat-intelligence/wallet/challenges/{challenge['challenge_id']}/verify",
        headers=_headers(user),
        json={
            "address": challenged.address,
            "signature": signed.signature.hex(),
            "chain_id": settings.blockchain_chain_id or 11155111,
        },
    )
    assert rejected.status_code == 400
    assert "does not recover" in rejected.json()["detail"]


def test_report_signature_binds_wallet_to_exact_revision_and_is_persisted():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    user = "wallet-report-" + uuid.uuid4().hex
    account = Account.create()
    report_id, revision_id = _create_report(client, user)

    ownership = client.post(
        "/api/threat-intelligence/wallet/challenges",
        headers=_headers(user),
        json={"address": account.address},
    ).json()
    signed_ownership = Account.sign_message(
        encode_defunct(text=ownership["message"]), private_key=account.key
    )
    verified = client.post(
        f"/api/threat-intelligence/wallet/challenges/{ownership['challenge_id']}/verify",
        headers=_headers(user),
        json={
            "address": account.address,
            "signature": signed_ownership.signature.hex(),
            "chain_id": settings.blockchain_chain_id or 11155111,
        },
    )
    assert verified.status_code == 200, verified.text

    challenge_response = client.post(
        f"/api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/signature/challenge",
        headers=_headers(user),
        json={"address": account.address},
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()
    signed_revision = Account.sign_message(
        encode_typed_data(full_message=challenge["typed_data"]), private_key=account.key
    )
    result = client.post(
        f"/api/threat-intelligence/signatures/{challenge['challenge_id']}/verify",
        headers=_headers(user),
        json={"signature": signed_revision.signature.hex()},
    )
    assert result.status_code == 200, result.text
    assert result.json()["verified"] is True
    assert result.json()["revision_id"] == revision_id

    replay = client.post(
        f"/api/threat-intelligence/signatures/{challenge['challenge_id']}/verify",
        headers=_headers(user),
        json={"signature": signed_revision.signature.hex()},
    )
    assert replay.status_code == 400

