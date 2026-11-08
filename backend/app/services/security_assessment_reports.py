"""Persisted, evidence-only exports for website security assessments."""
import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak

from backend.app.models.models import RemediationRecord, SecurityAssessment, SecurityAssessmentReport, SecurityFinding

REPORT_VERSION = "1.0"
FORMATS = {"json", "csv", "pdf"}
CATEGORY_LABELS = {
    "SECURITY_HEADERS": "Security headers", "COOKIES": "Cookies", "CORS": "CORS",
    "MIXED_CONTENT": "Mixed content", "CACHE_CONTROL": "Cache-Control",
    "PERMISSIONS_POLICY": "Permissions-Policy", "CROSS_ORIGIN_POLICY": "COOP, COEP and CORP",
    "TLS": "TLS and certificates", "HSTS": "HSTS", "REDIRECTS": "Redirect chains",
    "DNS": "DNS", "HTTP": "Server and version disclosure", "OTHER": "Other",
}


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _json(value):
    try:
        return json.loads(value or "{}") if isinstance(value, str) else (value or {})
    except (TypeError, ValueError):
        return {"raw": str(value)}


def _safe_text(value):
    return "" if value is None else str(value)


def _remediation(db, finding_id):
    return db.query(RemediationRecord).filter(RemediationRecord.finding_id == finding_id).first()


def build_report(db, assessment: SecurityAssessment) -> dict:
    findings = db.query(SecurityFinding).filter(SecurityFinding.assessment_id == assessment.id).order_by(SecurityFinding.id).all()
    statuses = Counter((item.status or "UNKNOWN").upper() for item in findings)
    severities = Counter((item.severity or "INFO").upper() for item in findings)
    remediation = {}
    serialized = []
    limitations = []
    category_items = {key: [] for key in CATEGORY_LABELS}
    for finding in findings:
        record = _remediation(db, finding.id)
        remediation_status = (record.status if record else finding.remediation_status or "OPEN").upper()
        item = {
            "finding_id": finding.id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "target_url": finding.target_url,
            "hostname": finding.hostname,
            "observed_value": finding.observed_value,
            "expected_value": finding.expected_value,
            "description": finding.description,
            "security_impact": finding.security_impact,
            "evidence": _json(finding.evidence_json),
            "remediation_guidance": finding.remediation,
            "verification_limitations": finding.verification_limitations,
            "remediation_status": remediation_status,
            "first_detected": _iso(finding.first_detected),
            "last_detected": _iso(finding.last_detected),
        }
        serialized.append(item)
        category = finding.category if finding.category in category_items else "OTHER"
        category_items[category].append(item["finding_id"])
        remediation[remediation_status] = remediation.get(remediation_status, 0) + 1
        if finding.verification_limitations:
            limitations.append(f"Finding #{finding.id}: {finding.verification_limitations}")
        if str(finding.status).upper() in {"UNKNOWN", "NOT_APPLICABLE"}:
            limitations.append(f"Finding #{finding.id} could not be fully verified ({finding.status}).")

    category_analysis = {
        key: {"label": label, "finding_count": len(category_items[key]), "finding_ids": category_items[key]}
        for key, label in CATEGORY_LABELS.items()
    }
    unknown = statuses.get("UNKNOWN", 0)
    not_applicable = statuses.get("NOT_APPLICABLE", 0)
    summary = {
        "target_domain": assessment.hostname,
        "assessment_id": assessment.id,
        "assessment_date": _iso(assessment.created_at),
        "completion_status": assessment.status,
        "completed_at": _iso(assessment.completed_at),
        "total_checks": len(findings),
        "passed": statuses.get("PASS", 0),
        "failed": statuses.get("FAIL", 0),
        "warnings": statuses.get("WARNING", 0),
        "unknown": unknown,
        "not_applicable": not_applicable,
        "severity_distribution": dict(severities),
        "overall_security_summary": "Failed or warning checks require review." if statuses.get("FAIL", 0) or statuses.get("WARNING", 0) else ("No failed checks were persisted; unknown checks remain unresolved." if unknown or not_applicable else "All persisted checks passed."),
    }
    return {
        "report_version": REPORT_VERSION,
        "report_generated_at": _iso(_now()),
        "assessment": {"id": assessment.id, "target_url": assessment.target_url, "hostname": assessment.hostname, "status": assessment.status, "created_at": _iso(assessment.created_at), "completed_at": _iso(assessment.completed_at)},
        "executive_summary": summary,
        "findings": serialized,
        "category_analysis": category_analysis,
        "remediation_summary": {"counts": remediation, "open_findings": [x["finding_id"] for x in serialized if x["remediation_status"] == "OPEN"], "in_progress_findings": [x["finding_id"] for x in serialized if x["remediation_status"] == "IN_PROGRESS"], "fixed_findings": [x["finding_id"] for x in serialized if x["remediation_status"] == "FIXED"], "accepted_risks": [x["finding_id"] for x in serialized if x["remediation_status"] == "ACCEPTED_RISK"], "false_positives": [x["finding_id"] for x in serialized if x["remediation_status"] == "FALSE_POSITIVE"], "recommended_priorities": [x["finding_id"] for x in serialized if x["severity"] in {"CRITICAL", "HIGH"} and x["remediation_status"] in {"OPEN", "REOPENED"}]},
        "technical_limitations": sorted(set(limitations)),
    }


def json_bytes(report):
    return json.dumps(report, indent=2, default=str, ensure_ascii=False).encode("utf-8")


def csv_bytes(report):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    columns = ["finding_id", "title", "category", "severity", "confidence", "status", "target_url", "hostname", "observed_value", "expected_value", "description", "security_impact", "evidence", "remediation_guidance", "verification_limitations", "remediation_status", "first_detected", "last_detected"]
    writer.writerow(columns)
    for finding in report["findings"]:
        writer.writerow([json.dumps(finding[column], default=str, ensure_ascii=False) if isinstance(finding[column], (dict, list)) else finding[column] for column in columns])
    if not report["findings"]:
        writer.writerow(["", "No persisted findings", "", "", "", report["assessment"]["status"]])
    return output.getvalue().encode("utf-8")


def _p(text, style):
    return Paragraph(escape(_safe_text(text)).replace("\n", "<br/>"), style)


def pdf_bytes(report):
    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=14)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, leading=10)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6)
    story = [_p("CYBERNEXUS Trust Intelligence — Website Security Assessment Report", title), _p(f"Report version {report['report_version']} · Generated {report['report_generated_at']}", small)]
    summary = report["executive_summary"]
    story += [_p("Executive summary", heading)]
    summary_rows = [[_p("Field", small), _p("Value", small)]] + [[_p(key.replace("_", " ").title(), small), _p(value, small)] for key, value in summary.items() if key != "severity_distribution"]
    summary_rows.append([_p("Severity distribution", small), _p(summary.get("severity_distribution"), small)])
    table = Table(summary_rows, colWidths=[1.9 * inch, 4.8 * inch], repeatRows=1)
    table.setStyle(TableStyle([["BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9eef2")], ["GRID", (0, 0), (-1, -1), 0.25, colors.grey], ["VALIGN", (0, 0), (-1, -1), "TOP"]]))
    story.append(table)
    story += [_p("Category-wise analysis", heading)]
    category_rows = [[_p("Category", small), _p("Findings", small), _p("Finding IDs", small)]]
    for item in report["category_analysis"].values():
        category_rows.append([_p(item["label"], small), _p(item["finding_count"], small), _p(item["finding_ids"] or "None", small)])
    category_table = Table(category_rows, colWidths=[2.6 * inch, 0.8 * inch, 3.3 * inch], repeatRows=1)
    category_table.setStyle(TableStyle([["BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9eef2")], ["GRID", (0, 0), (-1, -1), 0.25, colors.grey], ["VALIGN", (0, 0), (-1, -1), "TOP"]]))
    story.append(category_table)
    story += [_p("Detailed findings", heading)]
    for finding in report["findings"]:
        story.append(_p(f"#{finding['finding_id']} — {finding['title']} ({finding['severity']}, {finding['status']})", styles["Heading3"]))
        for key in ("category", "confidence", "hostname", "observed_value", "expected_value", "description", "security_impact", "evidence", "remediation_guidance", "verification_limitations", "remediation_status"):
            story.append(_p(f"{key.replace('_', ' ').title()}: {finding[key]}", small))
        story.append(Spacer(1, 7))
    story += [_p("Remediation summary", heading), _p(report["remediation_summary"], small), _p("Technical limitations", heading), _p(report["technical_limitations"] or "None recorded", small)]
    document.build(story)
    return output.getvalue()


def record_generation(db, assessment, actor, selected_format, finding_count, status="COMPLETED", error=""):
    row = SecurityAssessmentReport(assessment_id=assessment.id, generated_by=actor, report_version=REPORT_VERSION, format=selected_format, status=status, finding_count=finding_count, error=error, generated_at=_now())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def history(db, assessment_id, limit=50):
    rows = db.query(SecurityAssessmentReport).filter(SecurityAssessmentReport.assessment_id == assessment_id).order_by(SecurityAssessmentReport.generated_at.desc()).limit(limit).all()
    return [{"id": row.id, "assessment_id": row.assessment_id, "generated_by": row.generated_by, "report_version": row.report_version, "format": row.format, "status": row.status, "finding_count": row.finding_count, "error": row.error, "generated_at": row.generated_at} for row in rows]
