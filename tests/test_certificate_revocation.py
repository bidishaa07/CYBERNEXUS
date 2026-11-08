from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from cryptography.x509 import ocsp

from backend.app.engines.certificate_revocation import aggregate_revocation, check_crl, check_ocsp, distrust_and_ca_intelligence
from backend.app.engines.ca_reputation import lookup as lookup_ca_reputation
from backend.app.engines.safe_http import SafeResponse


def _ca(name="CA"):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
    cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(key,hashes.SHA256())
    return key,cert


def _leaf(issuer, issuer_key, revoked=False):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"example.com")])).issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]),False)
    builder=builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.OCSP,x509.UniformResourceIdentifier("https://ocsp.test/"))]),False).add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier("https://crl.test/ca.crl")],None,None,None)]),False)
    return key,builder.sign(issuer_key,hashes.SHA256())


def _crl(ca, ca_key, revoked_serial=None, expired=False):
    now=datetime.now(timezone.utc)
    builder=x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now-timedelta(hours=2)).next_update(now-timedelta(hours=1) if expired else now+timedelta(days=1))
    if revoked_serial is not None:
        builder=builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(revoked_serial).revocation_date(now-timedelta(hours=1)).build())
    return builder.sign(ca_key,hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def test_valid_crl_and_revoked_serial():
    ca_key,ca=_ca(); _,leaf=_leaf(ca,ca_key)
    response=SafeResponse(200,{"content-type":"application/pkix-crl"},_crl(ca,ca_key,leaf.serial_number))
    result=check_crl(leaf,ca,lambda _:response)
    assert result["status"] == "REVOKED"
    response=SafeResponse(200,{"content-type":"application/pkix-crl"},_crl(ca,ca_key))
    assert check_crl(leaf,ca,lambda _:response)["status"] == "GOOD"


def test_valid_ocsp_good_response_is_cryptographically_verified():
    ca_key,ca=_ca(); _,leaf=_leaf(ca,ca_key); now=datetime.now(timezone.utc)
    response=ocsp.OCSPResponseBuilder().add_response(leaf,ca,hashes.SHA1(),ocsp.OCSPCertStatus.GOOD,now-timedelta(minutes=1),now+timedelta(hours=1),None,None).responder_id(ocsp.OCSPResponderEncoding.NAME,ca).sign(ca_key,hashes.SHA256())
    safe_response=SafeResponse(200,{"content-type":"application/ocsp-response"},response.public_bytes(serialization.Encoding.DER))
    result=check_ocsp(leaf,ca,lambda url,body:safe_response)
    assert result["status"] == "GOOD"


def test_invalid_ocsp_signature_is_not_good():
    ca_key,ca=_ca(); _,leaf=_leaf(ca,ca_key); now=datetime.now(timezone.utc)
    response=ocsp.OCSPResponseBuilder().add_response(leaf,ca,hashes.SHA1(),ocsp.OCSPCertStatus.GOOD,now-timedelta(minutes=1),now+timedelta(hours=1),None,None).responder_id(ocsp.OCSPResponderEncoding.NAME,ca).sign(ca_key,hashes.SHA256())
    encoded=bytearray(response.public_bytes(serialization.Encoding.DER)); encoded[-1] ^= 0x01
    safe_response=SafeResponse(200,{"content-type":"application/ocsp-response"},bytes(encoded))
    result=check_ocsp(leaf,ca,lambda url,body:safe_response)
    assert result["status"] == "INVALID_RESPONSE"


def test_expired_and_invalid_crl_are_not_good():
    ca_key,ca=_ca(); _,leaf=_leaf(ca,ca_key)
    expired=SafeResponse(200,{},_crl(ca,ca_key,expired=True))
    assert check_crl(leaf,ca,lambda _:expired)["status"] == "UNKNOWN"
    other_key,other_ca=_ca("Other CA")
    invalid=SafeResponse(200,{},_crl(other_ca,other_key))
    assert check_crl(leaf,ca,lambda _:invalid)["status"] == "INVALID_RESPONSE"


def test_aggregation_keeps_conflicts_unknown():
    good={"status":"GOOD"}; unknown={"status":"UNKNOWN"}
    result=aggregate_revocation(good,unknown)
    assert result["status"] == "UNKNOWN"
    assert aggregate_revocation({"status":"REVOKED"},good)["status"] == "REVOKED"


def test_distrust_is_explicit_not_inferred(monkeypatch):
    ca_key,ca=_ca(); fingerprint=ca.fingerprint(hashes.SHA256()).hex()
    from backend.app.engines import certificate_revocation
    monkeypatch.setattr(certificate_revocation.settings,"certificate_distrust_fingerprints",fingerprint)
    result=distrust_and_ca_intelligence(ca,[ca])
    assert result["status"] == "DISTRUSTED"


def test_configured_ca_feed_match_is_provenance_backed(monkeypatch):
    ca_key,ca=_ca(); fingerprint=ca.fingerprint(hashes.SHA256()).hex()
    from backend.app.engines import ca_reputation
    monkeypatch.setattr(ca_reputation.settings,"ca_reputation_feed_url","https://feed.example/ca.json")
    monkeypatch.setattr(ca_reputation,"safe_fetch",lambda *args,**kwargs: SafeResponse(200,{"content-type":"application/json"},('{"records":[{"fingerprint_sha256":"'+fingerprint+'","status":"COMPROMISED","ca_reputation":"COMPROMISED","evidence":["advisory-123"]}]}').encode()))
    result=lookup_ca_reputation(ca,[ca])
    assert result["status"] == "COMPROMISED"
    assert result["source"] == "https://feed.example/ca.json"
