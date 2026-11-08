"""Explicit, auditable authorization for active website assessment checks."""
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from backend.app.models.models import SecurityAuthorization, SecurityAuthorizationEvent

class AuthorizationStopped(RuntimeError):
    """Raised when an active scan loses authorization while it is running."""

STATUSES = {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "REVOKED"}
DEFAULT_CATEGORIES = {"SECURITY_HEADERS", "COOKIES", "CORS", "MIXED_CONTENT", "CACHE_CONTROL", "PERMISSIONS_POLICY", "COOP_COEP_CORP", "TLS", "HSTS", "REDIRECTS", "DNS", "DISCLOSURE"}


def now():
    return datetime.now(timezone.utc)


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def hostname(value):
    parsed = urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").rstrip(".").lower()


def _list(value):
    if isinstance(value, str): value = [value]
    return [str(item).strip().lower().rstrip(".") for item in (value or []) if str(item).strip()]


def _categories(value):
    if isinstance(value, str): value = [value]
    return [str(item).strip().upper() for item in (value or []) if str(item).strip()]


def _event(db, row, actor, action, previous=None, note=""):
    db.add(SecurityAuthorizationEvent(authorization_id=row.id, actor=actor, action=action, previous_status=previous, new_status=row.approval_status, note=str(note or "")[:5000], created_at=now()))


def parse_time(value, field):
    if isinstance(value, datetime): return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try: return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc: raise ValueError(f"{field} must be an ISO timestamp") from exc


def create(db, requester, payload):
    target = hostname(payload.get("target_hostname") or payload.get("target") or "")
    organization = str(payload.get("authorized_organization") or "").strip()[:255]
    if not target or not organization: raise ValueError("target_hostname and authorized_organization are required")
    if payload.get("authorization_confirmation") is not True: raise ValueError("explicit authorization_confirmation=true is required")
    start = parse_time(payload.get("start_time") or now(), "start_time")
    expires = parse_time(payload.get("expiration_time") or payload.get("expires_at"), "expiration_time")
    if expires <= start: raise ValueError("expiration_time must be after start_time")
    scope = _list(payload.get("permitted_scope") or [target])
    if not scope or any(not hostname(item) for item in scope): raise ValueError("permitted_scope must contain hostnames")
    categories = _categories(payload.get("allowed_categories") or list(DEFAULT_CATEGORIES))
    if not categories or not set(categories).issubset(DEFAULT_CATEGORIES): raise ValueError("allowed_categories contains an unsupported category")
    row = SecurityAuthorization(target_hostname=target, authorized_organization=organization, requester_user_id=requester, authorization_confirmed=1, permitted_scope_json=json.dumps(scope), allowed_categories_json=json.dumps(categories), start_time=start, expires_at=expires, approval_status="PENDING", supporting_reference=str(payload.get("supporting_reference") or "")[:2048], created_at=now(), updated_at=now())
    db.add(row); db.flush(); _event(db, row, requester, "CREATED", None, "Authorization request submitted"); db.commit(); db.refresh(row); return row


def scope_allows(row, target, category=None, at=None):
    at = at or now(); target = hostname(target)
    if row.approval_status != "APPROVED" or not row.authorization_confirmed: return False
    if at < _aware(row.start_time) or at >= _aware(row.expires_at) or row.revoked_at: return False
    scopes = json.loads(row.permitted_scope_json or "[]")
    allowed = any(target == item or target.endswith("." + item) for item in scopes)
    if category and category.upper() not in json.loads(row.allowed_categories_json or "[]"): return False
    return bool(target and allowed)


def transition(db, row, actor, action, status, note=""):
    previous = row.approval_status
    if status not in STATUSES: raise ValueError("invalid_authorization_status")
    row.approval_status = status; row.updated_at = now()
    if status == "APPROVED": row.approved_by = actor; row.approved_at = now(); row.revoked_at = None
    if status == "REVOKED": row.revoked_at = now()
    _event(db, row, actor, action, previous, note); db.commit(); db.refresh(row); return row


def expire_if_needed(db, row):
    if row.approval_status == "APPROVED" and now() >= _aware(row.expires_at):
        previous = row.approval_status; row.approval_status = "EXPIRED"; row.updated_at = now(); _event(db, row, "system", "EXPIRED", previous, "Authorization expiration reached"); db.commit(); db.refresh(row)
    return row


def serialize(db, row, include_history=True):
    expire_if_needed(db, row)
    result = {"id": row.id, "assessment_id": row.assessment_id, "target_hostname": row.target_hostname, "authorized_organization": row.authorized_organization, "requester_user_id": row.requester_user_id, "authorization_confirmed": bool(row.authorization_confirmed), "permitted_scope": json.loads(row.permitted_scope_json or "[]"), "allowed_categories": json.loads(row.allowed_categories_json or "[]"), "start_time": row.start_time, "expires_at": row.expires_at, "approval_status": row.approval_status, "supporting_reference": row.supporting_reference, "approved_by": row.approved_by, "approved_at": row.approved_at, "revoked_at": row.revoked_at, "created_at": row.created_at, "updated_at": row.updated_at}
    if include_history:
        result["history"] = [{"id": event.id, "actor": event.actor, "action": event.action, "previous_status": event.previous_status, "new_status": event.new_status, "note": event.note, "created_at": event.created_at} for event in db.query(SecurityAuthorizationEvent).filter(SecurityAuthorizationEvent.authorization_id == row.id).order_by(SecurityAuthorizationEvent.created_at).all()]
    return result
