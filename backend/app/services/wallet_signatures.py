"""EIP-1193 wallet challenges and EIP-712 report signature verification."""
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from web3 import Web3
from backend.app.core.config import settings
from backend.app.models.models import WalletChallenge, WalletIdentity, BlockchainNetwork, DigitalSignature, ReportRevision, ThreatIntelligenceReport

def _now(): return datetime.now(timezone.utc)
def _as_utc(value):
    """Normalize SQLAlchemy's SQLite-naive timestamps for safe comparisons."""
    if value is None: return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
def _network_key(): return settings.blockchain_network_name or settings.blockchain_chain_id or "sepolia"
def _domain(): return urlparse(settings.public_app_url).hostname or "localhost"
def _chain_id(): return int(settings.blockchain_chain_id or 11155111)
def _address(value):
    try: return Web3.to_checksum_address(str(value))
    except Exception as exc: raise ValueError("invalid EVM wallet address") from exc

def _network(db):
    row = db.query(BlockchainNetwork).filter_by(network_key=_network_key()).first()
    if not row:
        row = BlockchainNetwork(network_key=_network_key(), name=settings.blockchain_network_name or "Sepolia", chain_id=str(_chain_id()), contract_address=settings.blockchain_contract_address or None, status="CONFIGURED", created_at=_now()); db.add(row); db.flush()
    return row

def ownership_challenge(db, principal, address, action="WALLET_OWNERSHIP"):
    address = _address(address)
    now = _now(); expires = now + timedelta(minutes=5); nonce = secrets.token_urlsafe(24); domain = _domain(); chain = _chain_id()
    message = f"{domain} wants you to verify ownership of:\n{domain}\n\nURI: {settings.public_app_url}\nVersion: 1\nChain ID: {chain}\nNonce: {nonce}\nIssued At: {now.isoformat().replace('+00:00','Z')}\nExpiration Time: {expires.isoformat().replace('+00:00','Z')}\nAction: {action}"
    row = WalletChallenge(challenge_id="wallet-" + uuid.uuid4().hex, owner_user_id=principal.user_id, wallet_address=address, domain=domain, action=action, chain_id=str(chain), nonce=nonce, message=message, expires_at=expires, created_at=now); db.add(row); db.commit()
    return {"challenge_id": row.challenge_id, "message": message, "domain": domain, "chain_id": chain, "expires_at": expires, "action": action}

def verify_ownership(db, principal, challenge_id, address, signature, chain_id):
    row = db.query(WalletChallenge).filter_by(challenge_id=challenge_id, owner_user_id=principal.user_id).first()
    if not row: raise LookupError("wallet challenge not found")
    if row.consumed_at: raise ValueError("wallet challenge already consumed")
    if _as_utc(row.expires_at) <= _now(): raise ValueError("wallet challenge expired")
    if int(chain_id) != int(row.chain_id): raise ValueError("wallet chain mismatch")
    expected = _address(row.wallet_address); supplied = _address(address)
    recovered = Account.recover_message(encode_defunct(text=row.message), signature=signature)
    if _address(recovered) != expected or supplied != expected: raise ValueError("wallet signature does not recover the challenged address")
    network = _network(db); identity = db.query(WalletIdentity).filter_by(network_id=network.id, address=expected).first()
    if identity and identity.owner_user_id != principal.user_id: raise ValueError("wallet is already linked to another application identity")
    if not identity: identity = WalletIdentity(owner_user_id=principal.user_id, network_id=network.id, address=expected, verification_status="VERIFIED", first_verified_at=_now(), created_at=_now()); db.add(identity)
    else: identity.verification_status="VERIFIED"; identity.first_verified_at=identity.first_verified_at or _now()
    row.consumed_at=_now(); db.commit()
    return {"verified": True, "wallet_id": identity.id, "address": expected, "network": network.name, "chain_id": int(network.chain_id)}

def _typed_data(report, revision, nonce, expires):
    verifying = settings.blockchain_contract_address if Web3.is_address(settings.blockchain_contract_address or "") else "0x0000000000000000000000000000000000000000"
    return {"types": {"EIP712Domain": [{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}], "ReportRevision": [{"name":"reportId","type":"string"},{"name":"revisionId","type":"uint256"},{"name":"reportHash","type":"bytes32"},{"name":"purpose","type":"string"},{"name":"nonce","type":"string"},{"name":"expiresAt","type":"uint256"}]}, "primaryType":"ReportRevision", "domain":{"name":"CYBERNEXUS Trust Intelligence","version":"1","chainId":_chain_id(),"verifyingContract":verifying}, "message":{"reportId":report.report_key,"revisionId":revision.id,"reportHash":"0x" + revision.canonical_report_hash,"purpose":"REPORT_REVISION_SIGNATURE","nonce":nonce,"expiresAt":int(expires.timestamp())}}

def signature_challenge(db, principal, report, revision, wallet_address):
    address = _address(wallet_address); network = _network(db); identity = db.query(WalletIdentity).filter_by(network_id=network.id, address=address, owner_user_id=principal.user_id, verification_status="VERIFIED").first()
    if not identity: raise PermissionError("wallet ownership must be verified before signing")
    now=_now(); expires=now+timedelta(minutes=5); nonce=secrets.token_urlsafe(24); typed=_typed_data(report, revision, nonce, expires)
    row=WalletChallenge(challenge_id="signature-"+uuid.uuid4().hex, owner_user_id=principal.user_id, wallet_address=address, domain=_domain(), action="SIGN_REPORT_REVISION", chain_id=str(_chain_id()), nonce=nonce, message=json.dumps(typed, sort_keys=True), typed_data_json=json.dumps(typed, separators=(",", ":")), report_id=report.id, revision_id=revision.id, report_hash=revision.canonical_report_hash, expires_at=expires, created_at=now); db.add(row); db.commit()
    return {"challenge_id":row.challenge_id,"typed_data":typed,"expires_at":expires,"report_id":report.id,"revision_id":revision.id,"report_hash":revision.canonical_report_hash}

def verify_signature(db, principal, challenge_id, signature):
    row=db.query(WalletChallenge).filter_by(challenge_id=challenge_id, owner_user_id=principal.user_id, action="SIGN_REPORT_REVISION").first()
    if not row: raise LookupError("signature challenge not found")
    if row.consumed_at: raise ValueError("signature challenge already consumed")
    if _as_utc(row.expires_at) <= _now(): raise ValueError("signature challenge expired")
    report=db.get(ThreatIntelligenceReport,row.report_id); revision=db.get(ReportRevision,row.revision_id)
    if not report or not revision or revision.canonical_report_hash != row.report_hash: raise ValueError("report revision commitment changed")
    typed=json.loads(row.typed_data_json or "{}"); recovered=Account.recover_message(encode_typed_data(full_message=typed), signature=signature); address=_address(recovered)
    if address != _address(row.wallet_address): raise ValueError("signature signer does not match verified wallet")
    network=_network(db); wallet=db.query(WalletIdentity).filter_by(network_id=network.id,address=address,owner_user_id=principal.user_id,verification_status="VERIFIED").first()
    if not wallet: raise PermissionError("wallet is not verified for this application identity")
    stored=DigitalSignature(report_id=report.id,revision_id=revision.id,wallet_id=wallet.id,algorithm="EIP-712",signature=signature,verification_status="VERIFIED",signature_type="EIP712",purpose="REPORT_REVISION_SIGNATURE",chain_id=str(_chain_id()),nonce=row.nonce,expires_at=row.expires_at,verified_at=_now(),evidence_json=json.dumps({"recovered_address":address,"domain":typed.get("domain"),"report_hash":revision.canonical_report_hash})); db.add(stored); row.consumed_at=_now(); db.commit()
    return {"verified":True,"signature_id":stored.id,"address":address,"report_id":report.id,"revision_id":revision.id,"algorithm":"EIP-712","verified_at":stored.verified_at}
