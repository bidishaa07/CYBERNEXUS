"""Persistence and normalization for the website security assessment layer.

This module deliberately consumes evidence already collected by the scanner. It
does not turn an unavailable network/provider result into a PASS.
"""
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError

from backend.app.models.models import (
    AssessmentAuthorization, AssessmentEvent, Scan, SecurityAssessment,
    SecurityCheckResult, SecurityEvidence, SecurityFinding,
)

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
STATUSES = {"PASS", "FAIL", "WARNING", "NOT_APPLICABLE", "UNKNOWN"}
CATEGORIES = {"SECURITY_HEADERS", "COOKIES", "TLS", "DNS", "HTTP", "OTHER"}


def _now():
    return datetime.now(timezone.utc)


def _json(value):
    return json.dumps(value if value is not None else {}, default=str, sort_keys=True)


def _text(value):
    if value is None or isinstance(value, str):
        return value
    return _json(value)


def _hostname(target_url: str) -> str:
    parsed = urlparse(target_url)
    return (parsed.hostname or "").rstrip(".").lower()


def normalize_finding(raw: dict, *, assessment_id: int, target_url: str, hostname: str,
                     checked_at: datetime | None = None) -> dict:
    """Normalize scanner/check output into the persisted security contract."""
    raw = raw or {}
    status = str(raw.get("status") or ("FAIL" if raw.get("issue") else "UNKNOWN")).upper()
    if status in {"AVAILABLE", "VALID", "OK", "PRESENT", "COMPLETED"}: status = "PASS"
    if status in {"UNAVAILABLE", "ERROR", "FAILED", "INVALID"}: status = "UNKNOWN" if status == "UNAVAILABLE" else "FAIL"
    if status not in STATUSES: status = "UNKNOWN"
    severity = str(raw.get("severity") or ("MEDIUM" if status == "FAIL" else "INFO")).upper()
    if severity not in SEVERITIES: severity = "INFO"
    category = str(raw.get("category") or "OTHER").upper()
    if category not in CATEGORIES: category = "OTHER"
    identifier = str(raw.get("check_identifier") or raw.get("check_id") or raw.get("issue") or "general_check").strip().lower().replace(" ", "_")[:120]
    return {
        "assessment_id": assessment_id,
        "target_url": target_url,
        "hostname": hostname,
        "category": category,
        "check_identifier": identifier,
        "title": str(raw.get("title") or raw.get("issue") or identifier.replace("_", " ").title())[:255],
        "description": str(raw.get("description") or raw.get("impact") or "")[:10000],
        "severity": severity,
        "confidence": str(raw.get("confidence") or ("HIGH" if status in {"PASS", "FAIL"} else "UNKNOWN")).upper()[:20],
        "status": status,
        "observed_value": _text(raw.get("observed_value", raw.get("evidence"))),
        "expected_value": _text(raw.get("expected_value")),
        "security_impact": str(raw.get("security_impact") or raw.get("impact") or "")[:10000],
        "remediation": str(raw.get("remediation") or "")[:10000],
        "evidence_json": _json(raw.get("technical_details", raw.get("evidence", raw))),
        "verification_limitations": str(raw.get("limitation") or raw.get("verification_limitations") or "")[:10000],
        "remediation_status": str(raw.get("remediation_status") or "OPEN").upper()[:30],
        "checked_at": checked_at or _now(),
    }


def _scanner_findings(result: dict, target_url: str, hostname: str) -> list[dict]:
    """Map the current network inspector's evidence without changing its output."""
    network = result.get("network") or {}
    findings = []
    headers = (network.get("http") or {}).get("headers") or {}
    header_labels = {
        "content-security-policy": ("content_security_policy", "Content Security Policy"),
        "strict-transport-security": ("strict_transport_security", "Strict Transport Security"),
        "x-content-type-options": ("x_content_type_options", "X-Content-Type-Options"),
        "x-frame-options": ("x_frame_options", "X-Frame-Options"),
        "referrer-policy": ("referrer_policy", "Referrer-Policy"),
    }
    for header, (identifier, label) in header_labels.items():
        if header in headers:
            findings.append({"category": "SECURITY_HEADERS", "check_identifier": identifier, "title": label,
                             "description": f"{label} was observed in the scanned response.", "status": "PASS",
                             "severity": "INFO", "confidence": "HIGH", "observed_value": headers[header],
                             "expected_value": "Header present", "evidence": {"header": header}})
        else:
            findings.append({"category": "SECURITY_HEADERS", "check_identifier": identifier, "title": f"Missing {label}",
                             "status": "FAIL", "severity": "MEDIUM", "confidence": "HIGH", "observed_value": "missing",
                             "expected_value": "Header present", "impact": "Browser protections may be weaker.",
                             "remediation": f"Configure {label} for the site.", "evidence": {"header": header},
                             "limitation": "Header absence alone does not prove exploitation."})
    for raw in network.get("findings") or []:
        item = dict(raw)
        item.setdefault("category", "SECURITY_HEADERS" if "header" in str(item.get("issue", "")).lower() else "HTTP")
        findings.append(item)
    tls = network.get("tls") or {}
    findings.append({"category": "TLS", "check_identifier": "tls_handshake", "title": "TLS handshake",
                     "status": "PASS" if tls.get("status") == "valid" else "UNKNOWN",
                     "severity": "INFO" if tls.get("status") == "valid" else "HIGH",
                     "confidence": "HIGH" if tls.get("status") == "valid" else "LOW",
                     "observed_value": tls.get("status"), "expected_value": "valid",
                     "evidence": tls, "limitation": "A failed handshake may reflect network unavailability."})
    dns = network.get("dns") or {}
    findings.append({"category": "DNS", "check_identifier": "dns_resolution", "title": "DNS resolution",
                     "status": "PASS" if dns.get("status") in {"available", "complete", "COMPLETED"} else "UNKNOWN",
                     "severity": "INFO", "confidence": "HIGH" if dns else "UNKNOWN",
                     "observed_value": dns.get("status"), "expected_value": "available", "evidence": dns})
    return findings


def attach_scan_to_assessment(db, row: SecurityAssessment, scan: Scan):
    """Attach one persisted scanner result to an existing assessment."""
    result = json.loads(scan.result_json) if scan.result_json else {}
    now = _now()
    seen_checks = set()
    for raw in _scanner_findings(result, scan.url, row.hostname):
        item = normalize_finding(raw, assessment_id=row.id, target_url=scan.url, hostname=row.hostname, checked_at=now)
        if item["check_identifier"] in seen_checks:
            continue
        seen_checks.add(item["check_identifier"])
        finding = SecurityFinding(**{k: v for k, v in item.items() if k != "checked_at"})
        finding.first_detected = now; finding.last_detected = now
        db.add(finding); db.flush()
        db.add(SecurityCheckResult(assessment_id=row.id, category=item["category"], check_identifier=item["check_identifier"], status=item["status"], result_json=item["evidence_json"], checked_at=now))
        db.add(SecurityEvidence(assessment_id=row.id, finding_id=finding.id, source="existing_scan", evidence_type=item["category"], details_json=item["evidence_json"], observed_at=now))
    row.scan_id = scan.id; row.target_url = scan.url; row.status = "COMPLETED"; row.completed_at = now
    _refresh_counts(db, row)
    return row


def create_assessment(db, *, user_id: str, target_url: str, scan_id: int | None = None, assessment_mode: str = "PASSIVE", authorization_id: int | None = None) -> SecurityAssessment:
    if not target_url or not _hostname(target_url):
        raise ValueError("target_url must contain a valid hostname")
    scan = db.get(Scan, scan_id) if scan_id is not None else None
    if scan_id is not None and not scan:
        raise LookupError("scan_not_found")
    result = json.loads(scan.result_json) if scan and scan.result_json else {}
    target = scan.url if scan else target_url
    mode = str(assessment_mode or "PASSIVE").upper()
    if mode not in {"PASSIVE", "ACTIVE"}: raise ValueError("assessment_mode must be PASSIVE or ACTIVE")
    row = SecurityAssessment(scan_id=scan.id if scan else None, user_id=user_id, target_url=target,
                             hostname=_hostname(target), status="COMPLETED" if scan else "PENDING", assessment_mode=mode, authorization_id=authorization_id)
    db.add(row); db.flush()
    db.add(AssessmentAuthorization(assessment_id=row.id, user_id=user_id, access_level="OWNER"))
    now = _now()
    if scan:
        attach_scan_to_assessment(db, row, scan)
    db.add(AssessmentEvent(assessment_id=row.id, actor=user_id, event_type="ASSESSMENT_CREATED", details_json=_json({"scan_id": scan_id})))
    _refresh_counts(db, row)
    db.commit(); db.refresh(row)
    return row


def _refresh_counts(db, assessment):
    rows = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment.id).all()
    assessment.finding_count = len(rows)
    assessment.pass_count = sum(x.status == "PASS" for x in rows)
    assessment.fail_count = sum(x.status == "FAIL" for x in rows)
    assessment.warning_count = sum(x.status == "WARNING" for x in rows)
    assessment.unknown_count = sum(x.status == "UNKNOWN" for x in rows)


def serialize_finding(row):
    return {"id": row.id, "assessment_id": row.assessment_id, "target_url": row.target_url, "hostname": row.hostname,
            "category": row.category, "check_identifier": row.check_identifier, "title": row.title, "description": row.description,
            "severity": row.severity, "confidence": row.confidence, "status": row.status, "observed_value": row.observed_value,
            "expected_value": row.expected_value, "security_impact": row.security_impact, "remediation": row.remediation,
            "evidence": json.loads(row.evidence_json or "{}"), "verification_limitations": row.verification_limitations,
            "remediation_status": row.remediation_status, "first_detected": row.first_detected, "last_detected": row.last_detected}


def serialize_assessment(db, row, include_findings=True):
    out = {"id": row.id, "scan_id": row.scan_id, "user_id": row.user_id, "target_url": row.target_url,
           "hostname": row.hostname, "status": row.status, "finding_count": row.finding_count, "pass_count": row.pass_count,
           "fail_count": row.fail_count, "warning_count": row.warning_count, "unknown_count": row.unknown_count,
           "assessment_mode": row.assessment_mode, "authorization_id": row.authorization_id, "stopped_reason": row.stopped_reason,
           "created_at": row.created_at, "completed_at": row.completed_at}
    if include_findings:
        out["findings"] = [serialize_finding(x) for x in db.query(SecurityFinding).filter(SecurityFinding.assessment_id == row.id).order_by(SecurityFinding.id).all()]
    return out


def can_access(db, row, principal, admin=False):
    if admin or row.user_id == principal.user_id:
        return True
    return db.query(AssessmentAuthorization).filter(AssessmentAuthorization.assessment_id == row.id, AssessmentAuthorization.user_id == principal.user_id).first() is not None
