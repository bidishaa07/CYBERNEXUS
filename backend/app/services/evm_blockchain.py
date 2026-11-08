"""EVM adapter for the ThreatIntelligence contract.

The adapter is testnet-only by policy. It never logs or returns private keys,
and it only marks a transaction confirmed after a successful receipt and the
expected contract event are both verified.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from backend.app.core.config import settings
from backend.app.models.models import BlockchainNetwork, BlockchainTransaction, ReportRevision, ThreatIntelligenceReport

try:
    from web3 import Web3
    from web3.exceptions import TimeExhausted
except ImportError:  # pragma: no cover - dependency is installed in production/test environments
    Web3 = None
    TimeExhausted = Exception

def _now(): return datetime.now(timezone.utc)
def _network_key(): return settings.blockchain_network_name or settings.blockchain_chain_id or "sepolia"

def _abi_path():
    path = Path(settings.blockchain_abi_path)
    return path if path.is_absolute() else Path.cwd() / path

def _load_abi():
    path = _abi_path()
    if not path.exists(): raise RuntimeError("ThreatIntelligence ABI artifact is missing; deploy/compile the blockchain project first")
    return json.loads(path.read_text(encoding="utf-8"))["abi"]

def _require_web3():
    if Web3 is None: raise RuntimeError("web3 dependency is not installed")

class EVMBlockchainAdapter:
    def __init__(self):
        _require_web3()
        if not settings.blockchain_rpc_url or not settings.blockchain_contract_address:
            raise RuntimeError("EVM RPC and contract address are required")
        if int(settings.blockchain_chain_id or 0) != 11155111:
            raise RuntimeError("Only Sepolia testnet chain ID 11155111 is supported")
        self.w3 = Web3(Web3.HTTPProvider(settings.blockchain_rpc_url, request_kwargs={"timeout": settings.blockchain_timeout_seconds}))
        if not self.w3.is_connected(): raise RuntimeError("EVM RPC is unavailable")
        if self.w3.eth.chain_id != int(settings.blockchain_chain_id): raise RuntimeError("EVM chain ID mismatch")
        self.address = self.w3.to_checksum_address(settings.blockchain_contract_address)
        if self.w3.eth.get_code(self.address) in (b"", b"\x00", "0x", "0x0"): raise RuntimeError("configured contract address has no bytecode")
        self.contract = self.w3.eth.contract(address=self.address, abi=_load_abi())

    def network_identity(self):
        return {"network": settings.blockchain_network_name or settings.blockchain_network_key, "chain_id": self.w3.eth.chain_id, "contract_address": self.address}

    @staticmethod
    def _bytes32(value):
        text = str(value or "")
        if text.startswith("0x") and len(text) == 66: return bytes.fromhex(text[2:])
        if re.fullmatch(r"[0-9a-fA-F]{64}", text): return bytes.fromhex(text)
        return Web3.keccak(text=text)

    def _account(self):
        if not settings.blockchain_private_key: raise RuntimeError("BLOCKCHAIN_PRIVATE_KEY is not configured")
        return self.w3.eth.account.from_key(settings.blockchain_private_key)

    def _event_verified(self, receipt, report_id, commitment):
        report_id = self._bytes32(report_id)
        commitment = self._bytes32(commitment)
        for event_name in ("ReportAnchored", "RevisionAnchored"):
            try:
                events = getattr(self.contract.events, event_name)().process_receipt(receipt)
            except Exception:
                continue
            for event in events:
                args = event.get("args", {})
                if bytes(args.get("reportId", b"")) == bytes(report_id) and bytes(args.get("commitment", b"")) == bytes(commitment):
                    return {"event": event_name, "report_id": report_id, "commitment": commitment, "log_index": event.get("logIndex")}
        return None

    def submit_revision(self, db, report: ThreatIntelligenceReport, revision: ReportRevision, metadata=""):
        existing = db.query(BlockchainTransaction).filter_by(network_id=self._network_id(db), revision_id=revision.id).first()
        if existing and existing.tx_hash and existing.status in {"PENDING", "SUBMITTED", "CONFIRMING", "UNKNOWN", "CONFIRMED"}:
            if existing.status == "PENDING":
                existing.status = "UNKNOWN"; db.commit()
            return self.refresh_transaction(db, existing.id)
        if existing and existing.status in {"SUBMITTED", "CONFIRMING", "CONFIRMED"}:
            return self.serialize(existing)
        account = self._account()
        report_id = self._bytes32(report.report_key)
        commitment = self._bytes32(revision.canonical_report_hash)
        network = db.get(BlockchainNetwork, self._network_id(db))
        if not existing:
            existing = BlockchainTransaction(network_id=network.id, revision_id=revision.id, report_id=report.id, commitment_id=str(revision.id), status="PENDING", confirmation_status="PENDING")
            db.add(existing); db.commit(); db.refresh(existing)
        nonce = self.w3.eth.get_transaction_count(account.address, "pending")
        if revision.revision_number == 1:
            call = self.contract.functions.anchorReport(report_id, commitment, str(metadata)[:255])
        else:
            call = self.contract.functions.addRevision(report_id, commitment, str(metadata)[:255])
        tx = call.build_transaction({"from": account.address, "nonce": nonce, "chainId": int(settings.blockchain_chain_id), "value": 0, "gas": self.w3.eth.estimate_gas({"from": account.address, "to": self.address, "data": call._encode_transaction_data()})})
        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        existing.tx_hash = tx_hash.hex(); existing.status="SUBMITTED"; existing.submitted_at=_now(); existing.last_checked_at=_now(); db.commit()
        return self.refresh_transaction(db, existing.id)

    def _network_id(self, db):
        network = db.query(BlockchainNetwork).filter_by(network_key=_network_key()).first()
        if not network:
            network = BlockchainNetwork(network_key=_network_key(), name=settings.blockchain_network_name or "Sepolia", chain_id=str(settings.blockchain_chain_id), rpc_url=None, contract_address=self.address, status="CONFIGURED", created_at=_now()); db.add(network); db.commit(); db.refresh(network)
        return network.id

    def refresh_transaction(self, db, transaction_id):
        row = db.get(BlockchainTransaction, transaction_id)
        if not row or not row.tx_hash: raise LookupError("transaction not found")
        try:
            receipt = self.w3.eth.get_transaction_receipt(row.tx_hash)
        except Exception:
            row.status = "UNKNOWN"; row.confirmation_status="UNKNOWN"; row.last_checked_at=_now(); db.commit(); return self.serialize(row)
        if receipt is None:
            row.status="CONFIRMING"; row.confirmation_status="PENDING"; row.last_checked_at=_now(); db.commit(); return self.serialize(row)
        row.block_number = receipt.get("blockNumber"); row.block_hash = receipt.get("blockHash").hex() if receipt.get("blockHash") else None; row.gas_used = receipt.get("gasUsed"); row.effective_gas_price = str(receipt.get("effectiveGasPrice")) if receipt.get("effectiveGasPrice") is not None else None; row.last_checked_at=_now()
        report = db.get(ThreatIntelligenceReport, row.report_id)
        revision = db.get(ReportRevision, row.revision_id)
        expected_event = self._event_verified(receipt, report.report_key if report else "", revision.canonical_report_hash if revision else "") if report and revision else None
        if not expected_event:
            row.status = "FAILED" if int(receipt.get("status", 0)) == 1 else "FAILED"
            row.confirmation_status = "INVALID_EVENT"; row.error = "Receipt did not contain the expected ThreatIntelligence commitment event"; db.commit(); return self.serialize(row)
        latest = self.w3.eth.block_number
        row.confirmation_status = "CONFIRMED" if latest - row.block_number + 1 >= settings.blockchain_confirmations else "CONFIRMING"
        row.status = "CONFIRMED" if row.confirmation_status == "CONFIRMED" and int(receipt.get("status", 0)) == 1 else ("FAILED" if int(receipt.get("status", 0)) == 0 else "CONFIRMING")
        row.metadata_json = json.dumps({"expected_event": expected_event}, sort_keys=True)
        db.commit(); return self.serialize(row)

    @staticmethod
    def serialize(row):
        return {"id": row.id, "status": row.status, "confirmation_status": row.confirmation_status, "transaction_hash": row.tx_hash, "block_number": row.block_number, "block_hash": row.block_hash, "gas_used": row.gas_used, "effective_gas_price": row.effective_gas_price, "revision_id": row.revision_id, "report_id": row.report_id, "last_checked_at": row.last_checked_at}
