"""Authorization-aware finding search and remediation workflow."""
import json
from datetime import datetime, timezone
from sqlalchemy import func, or_

from backend.app.models.models import (
    AssessmentAuthorization, FindingRemediationEvent, RemediationRecord, SecurityAssessment, SecurityFinding,
)
from backend.app.services.security_assessments import can_access, serialize_finding

REMEDIATION_STATUSES = {"OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "REOPENED"}
VERIFICATION_STATUSES = {"NOT_REQUESTED", "REQUESTED", "VERIFIED", "FAILED"}


def now():
    return datetime.now(timezone.utc)


def accessible_query(db, principal, admin=False):
    query = db.query(SecurityFinding).join(SecurityAssessment, SecurityAssessment.id == SecurityFinding.assessment_id).outerjoin(
        AssessmentAuthorization,
        (AssessmentAuthorization.assessment_id == SecurityAssessment.id) &
        (AssessmentAuthorization.user_id == principal.user_id),
    ).outerjoin(RemediationRecord, RemediationRecord.finding_id == SecurityFinding.id)
    if not admin:
        query = query.filter(or_(SecurityAssessment.user_id == principal.user_id, AssessmentAuthorization.id.isnot(None)))
    return query


def remediation_status_expression():
    """Treat a finding without a remediation row as OPEN without mutating it."""
    return func.coalesce(RemediationRecord.status, "OPEN")


def _record(db, finding_id):
    record = db.query(RemediationRecord).filter(RemediationRecord.finding_id == finding_id).first()
    if not record:
        record = RemediationRecord(finding_id=finding_id, status="OPEN", verification_status="NOT_REQUESTED")
        db.add(record); db.flush()
    return record


def remediation_dict(record):
    if not record:
        return {"status": "OPEN", "verification_status": "NOT_REQUESTED", "history": []}
    return {"id": record.id, "status": record.status, "note": record.note or "",
            "assigned_to": record.assigned_to, "proposed_fix": record.proposed_fix or "",
            "applied_fix": record.applied_fix or "", "verification_status": record.verification_status,
            "verification_note": record.verification_note or "", "verified_by": record.verified_by,
            "verified_at": record.verified_at, "updated_by": record.updated_by, "updated_at": record.updated_at}


def managed_finding(db, finding, include_history=True):
    result = serialize_finding(finding)
    record = db.query(RemediationRecord).filter(RemediationRecord.finding_id == finding.id).first()
    remediation = remediation_dict(record)
    if include_history:
        events = db.query(FindingRemediationEvent).filter(FindingRemediationEvent.finding_id == finding.id).order_by(FindingRemediationEvent.created_at.desc()).all()
        remediation["history"] = [{"id": item.id, "actor": item.actor, "action": item.action,
                                   "previous_status": item.previous_status, "new_status": item.new_status,
                                   "note": item.note or "", "verification_result": item.verification_result,
                                   "details": json.loads(item.details_json or "{}"), "created_at": item.created_at} for item in events]
    result["remediation"] = remediation
    return result


def update_remediation(db, finding, actor, payload, *, verify=False):
    record = _record(db, finding.id)
    previous = record.status
    requested = str(payload.get("status") or record.status).upper()
    if requested not in REMEDIATION_STATUSES:
        raise ValueError("invalid_remediation_status")
    if requested == "FIXED" and not verify and record.verification_status != "VERIFIED":
        raise ValueError("verification_required_before_fixed")
    if verify:
        passed = bool(payload.get("verified"))
        record.verification_status = "VERIFIED" if passed else "FAILED"
        record.verification_note = str(payload.get("note") or "")[:5000]
        record.verified_by = actor if passed else None
        record.verified_at = now() if passed else None
        record.status = "FIXED" if passed else "REOPENED"
        action = "VERIFIED" if passed else "VERIFICATION_FAILED"
        verification_result = record.verification_status
    else:
        record.status = requested
        if requested == "REOPENED":
            record.verification_status = "FAILED"
            record.verified_by = None
            record.verified_at = None
        if payload.get("request_verification") is True:
            record.verification_status = "REQUESTED"
        action = "STATUS_CHANGED"
        verification_result = record.verification_status
    if "note" in payload: record.note = str(payload.get("note") or "")[:5000]
    if "assigned_to" in payload: record.assigned_to = str(payload.get("assigned_to") or "")[:160] or None
    if "proposed_fix" in payload: record.proposed_fix = str(payload.get("proposed_fix") or "")[:10000]
    if "applied_fix" in payload: record.applied_fix = str(payload.get("applied_fix") or "")[:10000]
    record.updated_by = actor; record.updated_at = now()
    event = FindingRemediationEvent(finding_id=finding.id, actor=actor, action=action,
                                    previous_status=previous, new_status=record.status,
                                    note=str(payload.get("note") or "")[:5000],
                                    verification_result=verification_result,
                                    details_json=json.dumps({"assigned_to": record.assigned_to,
                                                              "proposed_fix": record.proposed_fix,
                                                              "applied_fix": record.applied_fix}))
    db.add(event); db.commit(); db.refresh(record)
    return record
