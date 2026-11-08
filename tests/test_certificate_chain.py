from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from backend.app.engines.certificate_chain import validate_path, summary

def make_cert(subject, issuer, key, issuer_key, ca, san=None, not_before=None, not_after=None):
    now=datetime.now(timezone.utc); builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,subject)])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,issuer)])).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(not_before or now-timedelta(minutes=1)).not_valid_after(not_after or now+timedelta(days=30)).add_extension(x509.BasicConstraints(ca=ca,path_length=2 if ca else None),critical=True)
    if san: builder=builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in san]),critical=False)
    if ca: builder=builder.add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
    return builder.sign(issuer_key,hashes.SHA256())

def pair():
    root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048); inter_key=rsa.generate_private_key(public_exponent=65537,key_size=2048); leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    root=make_cert("Root","Root",root_key,root_key,True); inter=make_cert("Intermediate","Root",inter_key,root_key,True); leaf=make_cert("example.com","Intermediate",leaf_key,inter_key,False,["example.com"])
    return root,inter,leaf

def test_complete_chain_is_cryptographically_valid():
    root,inter,leaf=pair(); result=validate_path("example.com",[(leaf,leaf.public_bytes(serialization.Encoding.DER)),(inter,inter.public_bytes(serialization.Encoding.DER)),(root,root.public_bytes(serialization.Encoding.DER))],[root])
    assert result["status"] == "VALID"

def test_missing_intermediate_is_incomplete_not_valid():
    root,_,leaf=pair(); result=validate_path("example.com",[(leaf,leaf.public_bytes(serialization.Encoding.DER))],[root])
    assert result["status"] == "INCOMPLETE"

def test_expired_and_hostname_mismatch_are_invalid():
    root,inter,leaf=pair()
    result=validate_path("wrong.example",[(leaf, b""),(inter,b""),(root,b"")],[root])
    assert "hostname_mismatch" in result["errors"]
    assert result["status"] == "INVALID"

def test_invalid_signature_and_circular_chain_are_not_valid():
    root,inter,leaf=pair(); wrong_key=rsa.generate_private_key(public_exponent=65537,key_size=2048); forged=make_cert("example.com","Intermediate",wrong_key,wrong_key,False,["example.com"])
    invalid=validate_path("example.com",[(forged,b""),(inter,b""),(root,b"")],[root])
    assert invalid["status"] == "INVALID" and any("invalid_signature" in x for x in invalid["errors"])
    circular=validate_path("example.com",[(leaf,b""),(inter,b""),(inter,b"")],[])
    assert circular["status"] == "INVALID" and "circular_chain" in circular["errors"]

def test_cross_signed_intermediate_selects_trusted_alternative_path():
    trusted_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    alternate_root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    intermediate_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    trusted_root=make_cert("Trusted Root","Trusted Root",trusted_key,trusted_key,True)
    alternate_root=make_cert("Alternate Root","Alternate Root",alternate_root_key,alternate_root_key,True)
    cross_signed=make_cert("Intermediate","Alternate Root",intermediate_key,alternate_root_key,True)
    trusted_intermediate=make_cert("Intermediate","Trusted Root",intermediate_key,trusted_key,True)
    leaf=make_cert("example.com","Intermediate",leaf_key,intermediate_key,False,["example.com"])

    result=validate_path(
        "example.com",
        [(leaf,leaf.public_bytes(serialization.Encoding.DER)),
         (cross_signed,cross_signed.public_bytes(serialization.Encoding.DER)),
         (trusted_intermediate,trusted_intermediate.public_bytes(serialization.Encoding.DER))],
        [trusted_root],
    )

    assert result["status"] == "VALID"
    assert len(result["alternative_paths"]) == 1
    assert result["alternative_paths"][0]["path_fingerprints"][-1] == _fingerprint_for_test(trusted_root)

def _fingerprint_for_test(cert):
    return cert.fingerprint(hashes.SHA256()).hex()
