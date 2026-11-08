"""Tamper-evident, sequence-aware append-only ledger for Phase 6.2."""
import hashlib
import json
import threading
from datetime import datetime, timezone
from sqlalchemy import text
from backend.app.models.models import AppendOnlyLedgerEvent, LedgerSequenceState

HASH_ALGORITHM = "SHA-256"
HASH_VERSION = "v2"
GENESIS_HASH = hashlib.sha256(b"CYBERNEXUS:THREAT_INTELLIGENCE_LEDGER:GENESIS:v1").hexdigest()
_process_lock = threading.RLock()

def _now():
    return datetime.now(timezone.utc)

def _timestamp(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def canonical_payload(payload):
    return json.dumps(payload or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def _v2_material(event):
    return {
        "sequence_number": event.sequence_number,
        "event_id": event.id,
        "event_type": event.event_type,
        "timestamp": _timestamp(event.occurred_at),
        "actor": event.actor_user_id,
        "canonical_payload_hash": event.payload_hash,
        "previous_event_hash": event.previous_event_hash or GENESIS_HASH,
    }

def _v1_hash(event):
    material = {"event_type": event.event_type, "report_id": event.report_id, "revision_id": event.revision_id, "actor": event.actor_user_id, "payload_hash": event.payload_hash, "previous_event_hash": event.previous_event_hash}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def event_hash(event):
    if event.hash_version == "v1":
        return _v1_hash(event)
    return hashlib.sha256(canonical_payload(_v2_material(event)).encode("utf-8")).hexdigest()

def record_event(db, event_type, actor, report_id=None, revision_id=None, details=None, evidence_refs=None, dedupe_key=None):
    """Append one event inside the caller's transaction.

    The process lock serializes local writers. The unique sequence and hash
    constraints provide the database guard; distributed deployments must retry
    the transaction after a serialization/unique conflict.
    """
    payload = canonical_payload(details or {})
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    dedupe_key = dedupe_key or f"{event_type}:{report_id}:{revision_id}:{payload_hash}"
    existing = db.query(AppendOnlyLedgerEvent).filter(AppendOnlyLedgerEvent.dedupe_key == dedupe_key).first()
    if existing:
        return existing
    with _process_lock:
        state = db.query(LedgerSequenceState).filter_by(id=1).with_for_update().first()
        if not state:
            state = LedgerSequenceState(id=1, next_sequence=1, updated_at=_now())
            db.add(state)
            db.flush()
        sequence = state.next_sequence
        state.next_sequence += 1
        state.updated_at = _now()
        # Flush the allocator update while the row lock/write lock is held.
        # PostgreSQL serializes this row with FOR UPDATE; SQLite serializes the
        # write transaction and the unique sequence index remains a backstop.
        db.flush()
        previous = db.query(AppendOnlyLedgerEvent).order_by(AppendOnlyLedgerEvent.sequence_number.desc(), AppendOnlyLedgerEvent.id.desc()).first()
        now = _now()
        event = AppendOnlyLedgerEvent(event_type=event_type, report_id=report_id, revision_id=revision_id, actor_user_id=actor, payload_hash=payload_hash, previous_event_hash=previous.event_hash if previous else GENESIS_HASH, event_hash="pending", payload_json=payload, occurred_at=now, hash_algorithm=HASH_ALGORITHM, hash_version=HASH_VERSION, evidence_refs_json=canonical_payload(evidence_refs or []), dedupe_key=dedupe_key)
        db.add(event)
        db.flush()
        event._ledger_initializing = True
        event.sequence_number = sequence
        event.event_hash = event_hash(event)
        db.flush()
        event._ledger_initializing = False
        return event

def verify_ledger(db):
    rows = db.query(AppendOnlyLedgerEvent).order_by(AppendOnlyLedgerEvent.sequence_number.asc(), AppendOnlyLedgerEvent.id.asc()).all()
    errors = []
    expected_sequence = 1
    previous_hash = GENESIS_HASH
    for row in rows:
        if row.sequence_number != expected_sequence:
            errors.append({"type": "SEQUENCE_GAP", "event_id": row.id, "expected": expected_sequence, "actual": row.sequence_number})
            break
        if row.hash_version == "v2" and (row.previous_event_hash or GENESIS_HASH) != previous_hash:
            errors.append({"type": "PREVIOUS_HASH_MISMATCH", "event_id": row.id, "expected": previous_hash, "actual": row.previous_event_hash})
            break
        if row.hash_version == "v1" and expected_sequence == 1 and row.previous_event_hash not in (None, ""):
            errors.append({"type": "GENESIS_MISMATCH", "event_id": row.id, "actual": row.previous_event_hash})
            break
        if row.hash_version not in {"v1", "v2"}:
            errors.append({"type": "UNSUPPORTED_HASH_VERSION", "event_id": row.id, "actual": row.hash_version})
            break
        computed = event_hash(row)
        if computed != row.event_hash:
            errors.append({"type": "EVENT_HASH_MISMATCH", "event_id": row.id, "expected": computed, "actual": row.event_hash})
            break
        if hashlib.sha256((row.payload_json or "").encode("utf-8")).hexdigest() != row.payload_hash:
            errors.append({"type": "PAYLOAD_HASH_MISMATCH", "event_id": row.id})
            break
        previous_hash = row.event_hash
        expected_sequence += 1
    return {"valid": not errors, "algorithm": HASH_ALGORITHM, "hash_version": HASH_VERSION, "genesis_hash": GENESIS_HASH, "event_count": len(rows), "verified_through_sequence": expected_sequence - 1, "first_inconsistency": errors[0] if errors else None}

def ledger_checkpoint(db):
    result = verify_ledger(db)
    last = db.query(AppendOnlyLedgerEvent).order_by(AppendOnlyLedgerEvent.sequence_number.desc()).first()
    result["checkpoint"] = {"sequence_number": last.sequence_number, "event_hash": last.event_hash} if last else None
    result["anchoring_status"] = "NOT_ANCHORED"
    return result
