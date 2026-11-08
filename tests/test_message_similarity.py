import hashlib
import json
from uuid import uuid4

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.models import MessageAnalysisMetadata, MessageAnalysisRecord, MessageContent, MessageSimilarityResult
from backend.app.services.message_similarity import correlate_messages, message_similarity_history

def _message(db, owner, text, sender, subject, indicators, brand=True):
    digest = hashlib.sha256(text.encode()).hexdigest()
    result = {"indicators": indicators, "indicator_intelligence": {"domain_spoofing": [{"brand": "PayPal", "official_domain": "paypal.com"}] if brand else []}}
    row = MessageAnalysisRecord(input_sha256=digest, source_type="TEXT", result_json=json.dumps(result)); db.add(row); db.flush()
    db.add(MessageContent(message_analysis_id=row.id, content_bytes=text.encode(), sha256=digest, content_type="text/plain"))
    db.add(MessageAnalysisMetadata(message_analysis_id=row.id, user_id=owner, input_type="TEXT", sender=sender, subject=subject, model_version="test-model-v1", analysis_status="COMPLETED")); db.flush()
    return row

def test_similar_messages_persist_explainable_results_and_relationships():
    Base.metadata.create_all(bind=engine); db = SessionLocal(); token = str(uuid4())
    try:
        body = "Your PayPal account is suspended. Verify your account immediately at https://paypa1.example/login"
        left = _message(db, token, body, "PayPal Support <security@paypal.com>", "Action required: verify your account", {"urls": ["https://paypa1.example/login"], "emails": ["security@paypal.com"], "phones": []})
        right = _message(db, token, body.replace("immediately", "today"), "PayPal Support <security@paypa1.com>", "Action required: verify your account", {"urls": ["https://paypa1.example/login"], "emails": ["security@paypa1.com"], "phones": []})
        db.commit(); result = correlate_messages(db, threshold=.5)
        match = next(item for item in result["results"] if str(left.id) in item["source_message"] or str(left.id) in item["related_message"])
        assert match["similarity_score"] >= .5
        assert match["matching_features"]
        assert "malicious" not in match["explanation"].lower()
        assert db.query(MessageSimilarityResult).filter(MessageSimilarityResult.similarity_score >= .5).count() >= 1
        assert message_similarity_history(db, "TEXT", str(left.id))
    finally:
        db.rollback(); db.close()

def test_unrelated_messages_do_not_create_similarity_result():
    Base.metadata.create_all(bind=engine); db = SessionLocal(); token = str(uuid4())
    try:
        left = _message(db, token, "Quarterly engineering meeting agenda and notes", "Engineering <team@example.org>", "Quarterly meeting", {"urls": [], "emails": [], "phones": []}, brand=False)
        right = _message(db, token, "Your package is ready for collection at the depot", "Courier <dispatch@shipping.example>", "Delivery update", {"urls": [], "emails": [], "phones": []}, brand=False)
        db.commit(); result = correlate_messages(db, threshold=.85)
        pair_ids = {f"TEXT:{left.id}", f"TEXT:{right.id}"}
        assert not [item for item in result["results"] if {item["source_message"], item["related_message"]} == pair_ids]
        history_left = message_similarity_history(db, "TEXT", str(left.id))
        history_right = message_similarity_history(db, "TEXT", str(right.id))
        assert not [item for item in history_left + history_right if {item["source_message"], item["related_message"]} == pair_ids]
    finally:
        db.rollback(); db.close()
