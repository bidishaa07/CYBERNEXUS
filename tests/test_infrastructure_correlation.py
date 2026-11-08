import json
from uuid import uuid4

from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.models import Scan, IndicatorRelationship, CorrelationEvidence
from backend.app.services.correlation_data import record_observation
from backend.app.services.infrastructure_correlation import run_infrastructure_correlation

def test_all_phase_42_shared_indicator_services_persist_evidence():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal(); token = str(uuid4())
    try:
        scans = []
        for name in (f"alpha-{token}.example", f"beta-{token}.example"):
            row = Scan(url=f"https://{name}", normalized_url=f"https://{name}/", domain=name, result_json=json.dumps({}))
            db.add(row); db.flush(); scans.append(row)
        shared = {
            "IP_ADDRESS": "203.0.113.10",
            "ASN": "AS64500",
            "NAMESERVER": f"ns-{token}.example",
            "CERTIFICATE_FINGERPRINT": "aa" * 32,
            "FAVICON_HASH": "bb" * 32,
            "CONTENT_FINGERPRINT": "cc" * 32,
        }
        for scan in scans:
            for kind, value in shared.items():
                record_observation(db, kind, value, source_analysis_type="scan", source_analysis_id=str(scan.id), source_provider="fixture")
        payment = f"upi:payee-{token}@bank"
        for source in (f"message-{token}-1", f"message-{token}-2"):
            record_observation(db, "PAYMENT_DESTINATION", payment, source_analysis_type="message", source_analysis_id=source, source_provider="fixture")
        db.commit()
        result = run_infrastructure_correlation(db)
        kinds = {item["relationship_type"] for item in result["relationships"]}
        assert {"shared_ip", "shared_asn", "shared_nameserver", "shared_certificate_fingerprint", "shared_favicon_hash", "shared_content_fingerprint", "shared_payment_destination"} <= kinds
        assert all(0 <= item["confidence"] <= 1 for item in result["relationships"])
        assert db.query(CorrelationEvidence).count() >= 7
    finally:
        db.rollback(); db.close()

def test_common_infrastructure_relationship_is_not_malicious_verdict():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal(); token = str(uuid4())
    try:
        left = record_observation(db, "DOMAIN", f"one-{token}.example", source_analysis_type="scan", source_analysis_id=f"a-{token}")
        right = record_observation(db, "DOMAIN", f"two-{token}.example", source_analysis_type="scan", source_analysis_id=f"b-{token}")
        ip = "198.51.100.20"
        record_observation(db, "IP_ADDRESS", ip, source_analysis_type="scan", source_analysis_id=f"a-{token}")
        record_observation(db, "IP_ADDRESS", ip, source_analysis_type="scan", source_analysis_id=f"b-{token}")
        db.commit(); result = run_infrastructure_correlation(db)
        match = [x for x in result["relationships"] if x["matching_indicator"] == ip]
        assert match and "ownership" in match[0]["explanation"]
    finally:
        db.rollback(); db.close()
