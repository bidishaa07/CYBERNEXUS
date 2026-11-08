"""External transaction receipt verification without private-key custody.

The application does not sign or submit transactions. An authorized external
signer/relayer may submit a transaction, after which this service verifies its
receipt and contract destination through the configured JSON-RPC endpoint.
"""
from datetime import datetime, timezone
import httpx
from backend.app.core.config import settings
from backend.app.models.models import BlockchainNetwork, BlockchainTransaction, ReportRevision

def _now():
    return datetime.now(timezone.utc)

def _network_key():
    return settings.blockchain_network_name or settings.blockchain_chain_id or "sepolia"

def configuration_status():
    return {"configured": bool(settings.blockchain_rpc_url and settings.blockchain_contract_address), "network": settings.blockchain_network_name or settings.blockchain_chain_id or None, "contract_address_configured": bool(settings.blockchain_contract_address), "private_key_custody": False}

def verify_configuration():
    base = configuration_status()
    if not base["configured"]:
        return {**base, "operational": False, "status": "NOT_CONFIGURED"}
    try:
        with httpx.Client(timeout=settings.blockchain_timeout_seconds) as client:
            def rpc(method, params):
                response = client.post(settings.blockchain_rpc_url, json={"jsonrpc":"2.0", "id":1, "method":method, "params":params})
                response.raise_for_status()
                body = response.json()
                if body.get("error"): raise RuntimeError("rpc_error")
                return body.get("result")
            chain_hex = rpc("eth_chainId", [])
            code = rpc("eth_getCode", [settings.blockchain_contract_address, "latest"])
        chain_id = int(chain_hex, 16) if chain_hex else None
        expected = int(settings.blockchain_chain_id) if settings.blockchain_chain_id else None
        code_present = bool(code and code not in {"0x", "0x0"})
        return {**base, "rpc_reachable": True, "configured_chain_id": expected, "rpc_chain_id": chain_id, "chain_id_matches": chain_id == expected, "contract_code_present": code_present, "operational": chain_id == expected and code_present, "status": "CONNECTED" if chain_id == expected and code_present else "INVALID_CONFIGURATION"}
    except Exception:
        return {**base, "rpc_reachable": False, "operational": False, "status": "PROVIDER_ERROR"}

def verify_external_receipt(db, revision: ReportRevision, tx_hash: str, actor: str):
    status = verify_configuration()
    if not status.get("operational"):
        return {"status": "NOT_CONFIGURED", "reason": "blockchain RPC, network key and contract address are required", "private_key_custody": False}
    tx_hash = str(tx_hash or "").strip()
    if not tx_hash or not tx_hash.startswith("0x"):
        raise ValueError("transaction hash must be a hexadecimal 0x value")
    headers = {"Content-Type": "application/json"}
    with httpx.Client(timeout=settings.blockchain_timeout_seconds) as client:
        receipt_response = client.post(settings.blockchain_rpc_url, headers=headers, json={"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":[tx_hash]})
        receipt_response.raise_for_status(); receipt_data = receipt_response.json()
        receipt = receipt_data.get("result")
        if not receipt:
            return {"status": "PENDING", "transaction_hash": tx_hash, "network": _network_key(), "commitment_binding": "NOT_VERIFIED"}
        destination = (receipt.get("to") or "").lower()
        configured_contract = settings.blockchain_contract_address.lower()
        if destination != configured_contract:
            return {"status": "INVALID_DESTINATION", "transaction_hash": tx_hash, "expected_contract": settings.blockchain_contract_address, "actual_destination": receipt.get("to"), "commitment_binding": "NOT_VERIFIED"}
        confirmed = str(receipt.get("status") or "").lower() == "0x1"
        network = db.query(BlockchainNetwork).filter_by(network_key=_network_key()).first()
        if not network:
            network = BlockchainNetwork(network_key=_network_key(), name=settings.blockchain_network_name or "Sepolia", chain_id=settings.blockchain_chain_id, contract_address=settings.blockchain_contract_address, status="CONFIGURED", created_at=_now()); db.add(network); db.flush()
        row = db.query(BlockchainTransaction).filter_by(network_id=network.id, revision_id=revision.id).first()
        if not row:
            row = BlockchainTransaction(network_id=network.id, revision_id=revision.id); db.add(row)
        row.tx_hash=tx_hash; row.status="CONFIRMED" if confirmed else "FAILED"; row.block_number=int(receipt.get("blockNumber"),16) if receipt.get("blockNumber") else None; row.confirmations=0; row.verified_at=_now(); row.metadata_json='{"commitment_binding":"NOT_VERIFIED","receipt_verified":true}'
        db.commit()
        return {"status": row.status, "transaction_hash": tx_hash, "network": network.network_key, "block_number": row.block_number, "contract_address": network.contract_address, "receipt_verified": True, "commitment_binding": "NOT_VERIFIED", "note": "Receipt and contract destination verified; commitment event binding requires the deployed contract ABI."}
