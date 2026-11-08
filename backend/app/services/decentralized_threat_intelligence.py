"""Phase 6.1 report revisions, commitments and provenance.

This service intentionally stops at a local, reproducible commitment. It does
not submit transactions, manage wallets, or claim blockchain anchoring.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from backend.app.models.models import (
    ThreatIntelligenceReport, ReportRevision, ReportCommitment,
    ProvenanceEvent, AppendOnlyLedgerEvent, IntegrityVerificationRecord,
)
from backend.app.services.ledger import record_event

DOMAIN_SEPARATOR = "CYBERNEXUS:THREAT_REPORT_COMMITMENT:v1"
HASH_ALGORITHM = "SHA-256"

def _now():
    return datetime.now(timezone.utc)

def _json_value(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    return value

def canonicalize_report(payload: dict) -> str:
    """Return canonical JSON for commitment hashing.

    v1 includes only stable report content. Transport fields, database IDs,
    signatures, blockchain metadata and generated timestamps are excluded.
    Missing optional fields become null; numbers are serialized by JSON's
    deterministic encoder and strings are UTF-8 encoded.
    """
    stable = {
        "schema": "threat-report-v1",
        "title": payload.get("title"),
        "description": payload.get("description") or "",
        "classification": payload.get("classification"),
        "severity": payload.get("severity"),
        "target": payload.get("target"),
        "findings": payload.get("findings") or [],
        "evidence_references": payload.get("evidence_references") or [],
        "source": payload.get("source"),
    }
    return json.dumps(_json_value(stable), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def calculate_commitment(payload: dict) -> dict:
    canonical = canonicalize_report(payload)
    digest = hashlib.sha256((DOMAIN_SEPARATOR + ":" + canonical).encode("utf-8")).hexdigest()
    return {"commitment": digest, "hash_algorithm": HASH_ALGORITHM, "canonicalization_version": "v1", "domain_separator": DOMAIN_SEPARATOR, "canonical_payload": canonical}

def _ledger(db, event_type, actor, report_id=None, revision_id=None, details=None):
    return record_event(db, event_type, actor, report_id=report_id, revision_id=revision_id, details=_json_value(details or {}))

def serialize_revision(db, revision):
    commitment = db.query(ReportCommitment).filter_by(revision_id=revision.id).first()
    return {"id": revision.id, "report_id": revision.report_id, "revision_number": revision.revision_number, "previous_revision_id": revision.previous_revision_id, "canonical_report_hash": revision.canonical_report_hash, "hash_algorithm": revision.hash_algorithm, "canonicalization_version": revision.canonicalization_version, "validation_state": revision.validation_state, "author_user_id": revision.author_user_id, "created_at": revision.created_at, "published_at": revision.published_at, "commitment": ({"value": commitment.commitment, "scope": commitment.commitment_scope, "domain_separator": commitment.domain_separator} if commitment else None)}

def serialize_report(db, report, include_revisions=True):
    result = {"id": report.id, "report_key": report.report_key, "owner_user_id": report.owner_user_id, "title": report.title, "description": report.description, "status": report.status, "visibility": report.visibility, "published_revision_id": report.published_revision_id, "created_at": report.created_at, "updated_at": report.updated_at}
    if include_revisions:
        result["revisions"] = [serialize_revision(db, row) for row in db.query(ReportRevision).filter_by(report_id=report.id).order_by(ReportRevision.revision_number.desc()).all()]
    return result

def create_report(db, owner, payload):
    title = str(payload.get("title") or "").strip()[:255]
    if not title: raise ValueError("title is required")
    report = ThreatIntelligenceReport(report_key="tir-" + uuid.uuid4().hex, owner_user_id=owner, title=title, description=str(payload.get("description") or "")[:20000], status="DRAFT", visibility="PRIVATE", created_at=_now(), updated_at=_now())
    db.add(report); db.flush()
    create_revision(db, report, owner, payload, previous=None)
    db.commit(); db.refresh(report)
    return report

def create_revision(db, report, author, payload, previous=None):
    previous = previous or db.query(ReportRevision).filter_by(report_id=report.id).order_by(ReportRevision.revision_number.desc()).first()
    if previous and previous.validation_state == "PUBLISHED":
        # Publishing a correction creates a new row; it never mutates the old one.
        pass
    revision_number = (previous.revision_number + 1) if previous else 1
    commitment = calculate_commitment(payload)
    state = str(payload.get("validation_state") or "DRAFT").upper()
    if state not in {"DRAFT", "PENDING", "VALIDATED", "PUBLISHED", "REJECTED"}: raise ValueError("invalid validation_state")
    now = _now()
    revision = ReportRevision(report_id=report.id, revision_number=revision_number, previous_revision_id=previous.id if previous else None, canonical_report_hash=commitment["commitment"], hash_algorithm=HASH_ALGORITHM, canonicalization_version="v1", canonical_payload=commitment["canonical_payload"], revision_metadata_json=json.dumps(_json_value(payload.get("metadata") or {}), sort_keys=True), author_user_id=author, validation_state=state, created_at=now, published_at=now if state == "PUBLISHED" else None)
    db.add(revision); db.flush()
    db.add(ReportCommitment(revision_id=revision.id, commitment=commitment["commitment"], hash_algorithm=HASH_ALGORITHM, domain_separator=DOMAIN_SEPARATOR, commitment_scope="LOCAL", created_at=now))
    db.add(ProvenanceEvent(report_id=report.id, revision_id=revision.id, actor_user_id=author, event_type="REVISION_CREATED", details_json=json.dumps({"revision_number": revision_number}), created_at=now))
    _ledger(db, "REVISION_CREATED", author, report.id, revision.id, {"revision_number": revision_number, "commitment": commitment["commitment"]})
    if state == "PUBLISHED":
        report.published_revision_id = revision.id; report.status = "PUBLISHED"
    report.updated_at = now
    return revision

def user_can_access(report, principal, admin=False):
    return bool(admin or report.owner_user_id == principal.user_id or report.owner_user_id in principal.legacy_ids)

def get_owned_report(db, report_id, principal, admin=False):
    report = db.get(ThreatIntelligenceReport, report_id)
    if not report or not user_can_access(report, principal, admin):
        raise LookupError("threat report not found")
    return report

def add_revision(db, report, principal, payload):
    if report.status == "ARCHIVED": raise ValueError("archived report cannot receive revisions")
    revision = create_revision(db, report, principal.user_id, payload)
    db.commit(); db.refresh(report)
    return revision

def commitment_for_revision(db, report, revision_id):
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision: raise LookupError("revision not found")
    return revision, db.query(ReportCommitment).filter_by(revision_id=revision.id).first()

def verify_local_commitment(db, report, revision_id, actor):
    revision, stored = commitment_for_revision(db, report, revision_id)
    if not stored: raise LookupError("commitment not found")
    actual = hashlib.sha256((stored.domain_separator + ":" + revision.canonical_payload).encode("utf-8")).hexdigest()
    status = "VERIFIED" if actual == stored.commitment == revision.canonical_report_hash else "MISMATCH"
    row = IntegrityVerificationRecord(report_id=report.id, revision_id=revision.id, commitment=stored.commitment, verification_source="LOCAL_CANONICAL_RECOMPUTATION", status=status, details_json=json.dumps({"computed": actual}), verified_at=_now())
    db.add(row); db.add(ProvenanceEvent(report_id=report.id, revision_id=revision.id, actor_user_id=actor, event_type="COMMITMENT_VERIFIED", details_json=json.dumps({"status": status}), created_at=_now())); db.commit()
    return {"report_id": report.id, "revision_id": revision.id, "stored_commitment": stored.commitment, "computed_commitment": actual, "status": status, "source": "LOCAL_CANONICAL_RECOMPUTATION"}

def provenance(db, report_id):
    return [{"id": x.id, "revision_id": x.revision_id, "actor_user_id": x.actor_user_id, "event_type": x.event_type, "source_type": x.source_type, "source_id": x.source_id, "ledger_event_id": x.ledger_event_id, "details": json.loads(x.details_json or "{}"), "created_at": x.created_at} for x in db.query(ProvenanceEvent).filter_by(report_id=report_id).order_by(ProvenanceEvent.created_at).all()]

def validation_history(db, report_id):
    from backend.app.models.models import ValidationRecord
    return [{"id": x.id, "revision_id": x.revision_id, "validator_user_id": x.validator_user_id, "validation_state": x.validation_state, "notes": x.notes, "created_at": x.created_at} for x in db.query(ValidationRecord).filter_by(report_id=report_id).order_by(ValidationRecord.created_at.desc()).all()]

def blockchain_metadata(db, report_id):
    from backend.app.models.models import BlockchainTransaction, BlockchainNetwork
    rows = db.query(BlockchainTransaction, BlockchainNetwork).join(BlockchainNetwork, BlockchainNetwork.id == BlockchainTransaction.network_id).join(ReportRevision, ReportRevision.id == BlockchainTransaction.revision_id).filter(ReportRevision.report_id == report_id).all()
    return [{"network": x.network_key, "name": x.name, "chain_id": x.chain_id, "transaction_hash": tx.tx_hash, "status": tx.status, "confirmations": tx.confirmations, "submitted_at": tx.submitted_at, "verified_at": tx.verified_at, "error": tx.error} for tx, x in rows]
