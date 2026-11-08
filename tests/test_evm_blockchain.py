from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.services.evm_blockchain import EVMBlockchainAdapter

def test_blockchain_status_validates_bytecode_and_does_not_expose_secrets():
    response = TestClient(app).get("/api/threat-intelligence/blockchain/status", headers={"X-Admin-Token": settings.admin_api_token})
    assert response.status_code == 200
    body = response.json()
    assert "rpc_url" not in body
    assert "private_key" not in body
    assert body["chain_id_matches"] is True
    assert body["operational"] is False
    assert body["contract_code_present"] is False

def test_bytes32_preserves_sha256_commitments():
    digest = "ab" * 32
    assert EVMBlockchainAdapter._bytes32(digest) == bytes.fromhex(digest)
