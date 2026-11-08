from backend.app.engines.certificate_risk import calculate
from backend.app.engines.risk import calculate as overall

def base():
    return {"certificate":{"public_key_algorithm":"_RSAPublicKey","public_key_size":2048,"signature_algorithm":"sha256","san":["example.com"]},"validation":{"status":"VALID","errors":[]},"revocation":{"status":"GOOD","certificates":[]},"tls_configuration":{"overall_grade":"A","version_security":{"grade":"A","deprecated_versions":[]},"cipher_security":{"grade":"A"},"certificate_algorithm_security":{"grade":"A"},"san_validation":{"status":"VALID"}},"ct_intelligence":{"anomalies":[]}}

def test_clean_certificate_has_independent_informational_score():
    result=calculate(base())
    assert result["score"]==0 and result["level"]=="Informational" and result["validation_status"]=="VALID"

def test_critical_evidence_is_scored_and_deduplicated():
    value=base(); value["validation"]={"status":"INVALID","errors":["expired:leaf","untrusted_or_missing_trust_anchor"]}; value["revocation"]={"status":"REVOKED","certificates":[]}; value["tls_configuration"]["san_validation"]={"status":"MISMATCH"}; value["ct_intelligence"]["anomalies"]=[{"finding_type":"issuer_change","fingerprint":"abc","confidence":"low","source":"crt.sh","explanation":"issuer changed"}]
    result=calculate(value)
    assert result["score"]>=80
    assert len({item["key"] for item in result["findings"]})==len(result["findings"])

def test_unknown_revocation_does_not_add_clean_or_malicious_points():
    value=base(); value["revocation"]={"status":"UNKNOWN","certificates":[]}; value["tls_configuration"]={"overall_grade":"UNKNOWN","version_security":{"grade":"UNKNOWN"},"cipher_security":{"grade":"UNKNOWN"},"certificate_algorithm_security":{"grade":"UNKNOWN"},"san_validation":{"status":"UNKNOWN"}}
    result=calculate(value)
    assert result["score"]==0 and result["revocation_status"]=="UNKNOWN"

def test_certificate_influence_is_bounded_and_explained():
    phishing={"score":0,"evidence":[]}; network={"evidence":[]}; threats={"findings":[]}; domain={"domain":{"brand_matches":[],"indicators":[]}}
    cert=calculate({**base(),"validation":{"status":"INVALID","errors":["expired:leaf"]}})
    result=overall(phishing,network,threats,domain,cert)
    assert result["certificate_influence"]["added_points"]<=25
    assert any(item["source"]=="certificate_risk" for item in result["contributions"])
