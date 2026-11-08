import ssl
from backend.app.engines import tls_configuration

def test_san_exact_wildcard_idn_and_mismatch():
    assert tls_configuration.validate_san("login.example.com", ["*.example.com"])["status"] == "VALID"
    assert tls_configuration.validate_san("deep.login.example.com", ["*.example.com"])["status"] == "MISMATCH"
    assert tls_configuration.validate_san("example.com", ["*.*.com"])["status"] == "MISMATCH"
    assert tls_configuration.validate_san("xn--bcher-kva.example", ["bücher.example"])["status"] == "VALID"
    assert tls_configuration.validate_san("192.0.2.10", [], ["192.0.2.10"])["status"] == "VALID"
    assert tls_configuration.validate_san("192.0.2.11", [], ["192.0.2.10"])["status"] == "MISMATCH"
    assert tls_configuration.validate_san("example.com", [])["status"] == "MISSING_SAN"

def test_cipher_grading_is_property_based():
    strong=tls_configuration.grade_cipher("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    weak=tls_configuration.grade_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.2", 112)
    assert strong["grade"] == "A" and strong["forward_secrecy"] and strong["aead"]
    assert weak["grade"] == "F"

def test_version_grading_distinguishes_deprecated_support():
    result=tls_configuration.grade_tls_versions([{"status":"SUPPORTED","version":"TLSv1.2"},{"status":"SUPPORTED","version":"TLSv1.3"}])
    assert result["grade"] == "A"
    deprecated=tls_configuration.grade_tls_versions([{"status":"SUPPORTED","version":"TLSv1.0"}])
    assert deprecated["grade"] == "C" and deprecated["deprecated_versions"] == ["TLSv1.0"]

def test_analyze_uses_actual_version_probe_results(monkeypatch):
    probes={"TLSv1.2":{"status":"SUPPORTED","version":"TLSv1.2","cipher_name":"ECDHE-RSA-AES128-GCM-SHA256","cipher_bits":128},"TLSv1.3":{"status":"SUPPORTED","version":"TLSv1.3","cipher_name":"TLS_AES_128_GCM_SHA256","cipher_bits":128}}
    def fake_probe(host, version):
        label={ssl.TLSVersion.TLSv1_2:"TLSv1.2",ssl.TLSVersion.TLSv1_3:"TLSv1.3"}.get(version,"TLSv1.0")
        if label not in probes: raise ssl.SSLError("unsupported")
        return probes[label]
    monkeypatch.setattr(tls_configuration,"_handshake",fake_probe)
    result=tls_configuration.analyze("example.com",{"public_key_algorithm":"_RSAPublicKey","public_key_size":2048,"signature_algorithm":"sha256" ,"san":["example.com"],"san_ip":[]})
    assert result["status"] == "ANALYZED"
    assert result["version_security"]["supported_versions"] == ["TLSv1.2","TLSv1.3"]
    assert result["san_validation"]["status"] == "VALID"
