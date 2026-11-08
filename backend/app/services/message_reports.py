"""Exports and persisted report loading; never recalculates analysis results."""
import csv
import io
import json
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

REPORT_VERSION = "1.0"

def bundle(kind: str, row, metadata=None):
    result=json.loads(row.result_json)
    return {"report_version": REPORT_VERSION, "analysis_id": row.id, "analysis_type": kind, "analysis_timestamp": (metadata.created_at if metadata else getattr(row, "created_at", None)), "metadata": {"sender": getattr(metadata, "sender", None), "subject": getattr(metadata, "subject", None), "input_type": getattr(metadata, "input_type", kind.upper()), "model_version": getattr(metadata, "model_version", None), "llm_status": getattr(metadata, "llm_status", None)}, "automated_assessment": {"classification": result.get("classification"), "risk_score": result.get("score"), "ml": result.get("ml"), "rules": result.get("evidence", [])}, "indicators": result.get("indicator_intelligence", result.get("indicators", {})), "authentication": result.get("authentication", result.get("trusted_authentication", {})), "llm": result.get("llm", {}), "limitations": [result.get("limitation")] if result.get("limitation") else ["Observed evidence and model interpretation are reported separately."], "evidence_timestamp": result.get("checked_at")}

def csv_bytes(report: dict) -> bytes:
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["field", "value"])
    def add(prefix, value):
        if isinstance(value, (dict,list)): value=json.dumps(value, default=str)
        writer.writerow([prefix, value])
    for key,value in report.items(): add(key,value)
    return output.getvalue().encode("utf-8")

def pdf_bytes(report: dict) -> bytes:
    output=io.BytesIO(); document=canvas.Canvas(output,pagesize=letter); width,height=letter; y=height-45
    document.setTitle(f"Digital Trust Message Analysis {report['analysis_id']}")
    document.setFont("Helvetica-Bold", 15); document.drawString(42,y,"Digital Trust Intelligence - Message Report"); y-=24
    document.setFont("Helvetica",9)
    for key,value in [("Report version",report["report_version"]),("Analysis ID",report["analysis_id"]),("Analysis type",report["analysis_type"]),("Classification",report["automated_assessment"].get("classification")),("Risk score",report["automated_assessment"].get("risk_score")),("Model version",report["metadata"].get("model_version")),("LLM status",report["metadata"].get("llm_status"))]:
        document.drawString(42,y,f"{key}: {value}"); y-=14
    y-=8; document.setFont("Helvetica-Bold",11); document.drawString(42,y,"Evidence and findings"); y-=16; document.setFont("Helvetica",8)
    lines=json.dumps({"rules":report["automated_assessment"].get("rules"),"indicators":report["indicators"],"authentication":report["authentication"],"llm":report["llm"],"limitations":report["limitations"]},default=str).splitlines()
    text=" ".join(lines)
    for index in range(0,len(text),105):
        if y < 45: document.showPage(); y=height-45; document.setFont("Helvetica",8)
        document.drawString(42,y,text[index:index+105]); y-=11
    document.save(); return output.getvalue()
