import pytest
from uuid import uuid4
from backend.app.db.session import Base, engine, SessionLocal
from backend.app.models.models import IndicatorObservation, IndicatorRelationship
from backend.app.services.correlation_data import record_observation, record_relationship
from backend.app.engines.indicator_normalization import normalize_indicator, normalize_url, stable_identifier
from backend.app.engines.correlation import _canonical_domain

@pytest.fixture()
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback(); session.close()

def test_normalizes_supported_indicator_types():
    assert normalize_indicator("DOMAIN", "Exämple.COM.")[1] == "xn--exmple-cua.com"
    assert normalize_indicator("IP_ADDRESS", "2001:0db8:0:0::1")[1] == "2001:db8::1"
    assert normalize_indicator("ASN", " as0042 ")[1] == "AS42"
    assert normalize_indicator("EMAIL_ADDRESS", "A@ExAmple.COM")[1] == "A@example.com"
    assert normalize_url("HTTPS://Example.COM/a?b=2&a=1#fragment") == "https://example.com/a?a=1&b=2"
    assert stable_identifier("DOMAIN", "example.com").startswith("domain:")

def test_rejects_ambiguous_or_invalid_values():
    with pytest.raises(ValueError): normalize_indicator("IP_ADDRESS", "not-an-ip")
    with pytest.raises(ValueError): normalize_indicator("PAYMENT_DESTINATION", "same")

def test_existing_exact_domain_correlation_uses_canonical_domain():
    assert _canonical_domain("HTTPS://Example.COM.") == "example.com"

def test_observations_are_deduplicated_and_counted(db):
    source_id = f"phase41-observation-dedup-{uuid4()}"
    _, first = record_observation(db, "DOMAIN", "Example.com.", source_analysis_type="test", source_analysis_id=source_id, source_provider="rdap")
    _, second = record_observation(db, "DOMAIN", "example.com", source_analysis_type="test", source_analysis_id=source_id, source_provider="rdap")
    db.commit()
    assert first.id == second.id
    row = db.query(IndicatorObservation).filter_by(normalized_value="example.com", source_analysis_type="test", source_analysis_id=source_id).one()
    assert row.observation_count == 2

def test_relationships_are_deduplicated(db):
    domain, _ = record_observation(db, "DOMAIN", "example.com", source_analysis_type="scan", source_analysis_id="2")
    ip, _ = record_observation(db, "IP_ADDRESS", "8.8.8.8", source_analysis_type="scan", source_analysis_id="2")
    first = record_relationship(db, domain, ip, "resolves_to", analysis_type="scan", analysis_id="2", confidence=.9)
    second = record_relationship(db, domain, ip, "resolves_to", analysis_type="scan", analysis_id="2", confidence=.8)
    db.commit()
    assert first.id == second.id
    matches = db.query(IndicatorRelationship).filter_by(source_indicator_id=domain.id, target_indicator_id=ip.id, relationship_type="resolves_to").all()
    assert len(matches) == 1
    assert matches[0].confidence == .9
