"""Explainable message similarity and impersonation-pattern correlation."""
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.utils import parseaddr
from urllib.parse import urlsplit

from backend.app.core.config import settings
from backend.app.engines.indicator_normalization import normalize_domain, normalize_email, normalize_phone, normalize_url
from backend.app.models.models import EmailAnalysis, EmailRawMessage, MessageAnalysisMetadata, MessageAnalysisRecord, MessageContent, MessageSimilarityResult
from backend.app.services.correlation_data import record_evidence, record_observation, record_relationship
from backend.app.models.models import ThreatIndicator

TOKEN_RE = re.compile(r"[\w@.-]+", re.UNICODE)

def _now():
    return datetime.now(timezone.utc)

def _json(value, fallback=None):
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return fallback if fallback is not None else {}

def _tokens(value):
    return [item.casefold() for item in TOKEN_RE.findall(value or "")]

def _cosine(left, right):
    if not left or not right:
        return None
    a, b = Counter(left), Counter(right)
    common = set(a) & set(b)
    numerator = sum(a[item] * b[item] for item in common)
    denominator = math.sqrt(sum(x * x for x in a.values())) * math.sqrt(sum(x * x for x in b.values()))
    return numerator / denominator if denominator else 0.0

def _text_similarity(left, right):
    if not left and not right:
        return None
    return SequenceMatcher(None, (left or "").casefold(), (right or "").casefold()).ratio()

def _source_key(kind, identifier):
    return f"{kind.lower()}:{identifier}"

def _sender_parts(sender):
    display, address = parseaddr(sender or "")
    domain = ""
    if "@" in address:
        try:
            domain = normalize_domain(address.rsplit("@", 1)[1])
        except ValueError:
            domain = address.rsplit("@", 1)[1].casefold()
    return display.casefold(), address.casefold(), domain

def _normalize_indicator_sets(result):
    raw = result.get("indicators") or {}
    values = set()
    urls = set()
    domains = set()
    emails = set()
    phones = set()
    for value in raw.get("urls") or []:
        try:
            normalized = normalize_url(value); urls.add(normalized); domains.add(urlsplit(normalized).hostname)
        except ValueError:
            continue
    for value in raw.get("emails") or []:
        try:
            normalized = normalize_email(value); emails.add(normalized); domains.add(normalized.rsplit("@", 1)[1])
        except ValueError:
            continue
    for value in raw.get("phones") or []:
        normalized = normalize_phone(value)
        if normalized:
            phones.add(normalized)
    values.update(urls); values.update(emails); values.update(phones)
    for finding in (result.get("indicator_intelligence") or {}).get("domain_spoofing") or []:
        for key in ("observed_domain", "official_domain"):
            if finding.get(key):
                try: domains.add(normalize_domain(finding[key]))
                except ValueError: pass
    return {"all": values | domains, "urls": urls, "domains": domains, "emails": emails, "phones": phones}

def _snapshot(db, metadata):
    if metadata.message_analysis_id:
        row = db.get(MessageAnalysisRecord, metadata.message_analysis_id)
        if not row:
            return None
        result = _json(row.result_json)
        content = db.query(MessageContent).filter_by(message_analysis_id=row.id).first()
        body = content.content_bytes.decode(errors="replace") if content else ""
        kind, identifier = "TEXT", str(row.id)
        sender = metadata.sender or ""
        subject = metadata.subject or ""
    elif metadata.email_analysis_id:
        row = db.get(EmailAnalysis, metadata.email_analysis_id)
        if not row:
            return None
        result = _json(row.result_json)
        raw = db.query(EmailRawMessage).filter_by(analysis_id=row.id).first()
        body = raw.raw_bytes.decode(errors="replace") if raw else ""
        kind, identifier = "EML", str(row.id)
        sender_data = result.get("sender") or {}
        sender = metadata.sender or sender_data.get("from") or ""
        subject = metadata.subject or sender_data.get("subject") or ""
    else:
        return None
    display, address, domain = _sender_parts(sender)
    return {"type": kind, "id": identifier, "key": _source_key(kind, identifier), "body": body, "subject": subject or "", "sender": sender, "display_name": display, "sender_address": address, "sender_domain": domain, "result": result, "indicators": _normalize_indicator_sets(result), "model_version": metadata.model_version or "unknown"}

def _features(left, right):
    subject = _text_similarity(left["subject"], right["subject"])
    body = _cosine(_tokens(left["body"]), _tokens(right["body"]))
    display = _text_similarity(left["display_name"], right["display_name"]) if left["display_name"] or right["display_name"] else None
    sender_domain = _text_similarity(left["sender_domain"], right["sender_domain"]) if left["sender_domain"] or right["sender_domain"] else None
    indicator_overlap = _overlap(left["indicators"]["all"], right["indicators"]["all"])
    url_overlap = _overlap(left["indicators"]["urls"] | left["indicators"]["domains"], right["indicators"]["urls"] | right["indicators"]["domains"])
    left_brands = _brand_keys(left["result"]); right_brands = _brand_keys(right["result"])
    brand_overlap = _overlap(left_brands, right_brands)
    length_similarity = 1 - min(abs(len(left["body"]) - len(right["body"])) / max(len(left["body"]), len(right["body"]), 1), 1)
    return {"subject_similarity": subject, "body_similarity": body, "display_name_similarity": display, "sender_domain_similarity": sender_domain, "indicator_overlap": indicator_overlap, "url_pattern_overlap": url_overlap, "brand_impersonation_overlap": brand_overlap, "structure_similarity": length_similarity}

def _overlap(left, right):
    if not left and not right:
        return None
    union = left | right
    return len(left & right) / len(union) if union else 0.0

def _brand_keys(result):
    values = set()
    for finding in (result.get("indicator_intelligence") or {}).get("domain_spoofing") or []:
        for key in ("brand", "official_domain"):
            if finding.get(key): values.add(str(finding[key]).casefold())
    return values

def _score(features):
    weights = {"body_similarity": .32, "subject_similarity": .16, "sender_domain_similarity": .12, "display_name_similarity": .08, "url_pattern_overlap": .12, "indicator_overlap": .10, "brand_impersonation_overlap": .07, "structure_similarity": .03}
    available = [(key, value, weights[key]) for key, value in features.items() if value is not None]
    if not available:
        return 0.0, []
    total_weight = sum(item[2] for item in available)
    score = sum(item[1] * item[2] for item in available) / total_weight
    matches = [{"feature": key, "value": round(value, 4), "weight": weight} for key, value, weight in available if value >= .5]
    return round(score, 4), matches

def _explanation(matches):
    labels = {"body_similarity": "similar body wording", "subject_similarity": "similar subject", "sender_domain_similarity": "similar sender domain", "display_name_similarity": "similar display name", "url_pattern_overlap": "overlapping URL or domain indicators", "indicator_overlap": "shared extracted indicators", "brand_impersonation_overlap": "shared brand-impersonation evidence", "structure_similarity": "similar message structure"}
    return "; ".join(labels[item["feature"]] for item in matches) or "No strong shared message features were identified."

def _upsert_result(db, left, right, score, features, matches):
    source, related = (left, right) if (left["key"], left["type"]) < (right["key"], right["type"]) else (right, left)
    row = db.query(MessageSimilarityResult).filter_by(source_message_type=source["type"], source_message_id=source["id"], related_message_type=related["type"], related_message_id=related["id"]).first()
    now = _now(); evidence = {"matching_features": matches, "explanation": _explanation(matches), "limitations": ["Similarity alone does not establish malicious intent.", "Common templates and legitimate newsletters can produce similarity."]}
    if row:
        row.last_observed = now; row.similarity_score = score; row.matching_features_json = json.dumps(features); row.evidence_json = json.dumps(evidence)
    else:
        row = MessageSimilarityResult(source_message_type=source["type"], source_message_id=source["id"], related_message_type=related["type"], related_message_id=related["id"], similarity_score=score, matching_features_json=json.dumps(features), detection_method="token cosine, sequence similarity and deterministic indicator overlap", evidence_json=json.dumps(evidence), model_version=f"{source['model_version']}|{related['model_version']}", first_observed=now, last_observed=now)
        db.add(row)
    left_indicator, _ = record_observation(db, "MESSAGE_IDENTIFIER", source["key"], source_analysis_type="message", source_analysis_id=source["key"], source_provider="message-similarity")
    right_indicator, _ = record_observation(db, "MESSAGE_IDENTIFIER", related["key"], source_analysis_type="message", source_analysis_id=related["key"], source_provider="message-similarity")
    relationship = record_relationship(db, left_indicator, right_indicator, "similar_message", analysis_type="message", analysis_id=source["key"], confidence=score, status="observed")
    record_evidence(db, relationship_id=relationship.id, evidence_type="message_similarity", source="message_similarity_engine", details=evidence, confidence=score)
    return row

def correlate_messages(db, *, threshold=None, max_pairs=None):
    snapshots = [_snapshot(db, metadata) for metadata in db.query(MessageAnalysisMetadata).order_by(MessageAnalysisMetadata.created_at).all()]
    snapshots = [item for item in snapshots if item]
    threshold = settings.message_similarity_threshold if threshold is None else threshold
    max_pairs = settings.message_similarity_max_pairs if max_pairs is None else max_pairs
    results = []
    for index, left in enumerate(snapshots):
        for right in snapshots[index + 1:]:
            if len(results) >= max_pairs:
                break
            features = _features(left, right); score, matches = _score(features)
            if score < threshold:
                continue
            row = _upsert_result(db, left, right, score, features, matches)
            results.append({"id": row.id, "source_message": f"{row.source_message_type}:{row.source_message_id}", "related_message": f"{row.related_message_type}:{row.related_message_id}", "similarity_score": row.similarity_score, "matching_features": matches, "explanation": _explanation(matches), "model_version": row.model_version, "first_observed": row.first_observed, "last_observed": row.last_observed})
        if len(results) >= max_pairs:
            break
    db.commit()
    return {"results": results, "count": len(results), "threshold": threshold, "method": "explainable message similarity; not a fraud verdict", "generated_at": _now().isoformat()}

def message_similarity_history(db, analysis_type=None, analysis_id=None):
    query = db.query(MessageSimilarityResult)
    if analysis_type and analysis_id:
        query = query.filter(((MessageSimilarityResult.source_message_type == analysis_type.upper()) & (MessageSimilarityResult.source_message_id == str(analysis_id))) | ((MessageSimilarityResult.related_message_type == analysis_type.upper()) & (MessageSimilarityResult.related_message_id == str(analysis_id))))
    return [{"id": row.id, "source_message": f"{row.source_message_type}:{row.source_message_id}", "related_message": f"{row.related_message_type}:{row.related_message_id}", "similarity_score": row.similarity_score, "matching_features": _json(row.matching_features_json), "evidence": _json(row.evidence_json), "model_version": row.model_version, "first_observed": row.first_observed, "last_observed": row.last_observed} for row in query.order_by(MessageSimilarityResult.last_observed.desc()).all()]
