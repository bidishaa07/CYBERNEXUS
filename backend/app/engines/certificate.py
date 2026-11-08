from backend.app.engines.certificate_chain import collect
from backend.app.engines.tls_configuration import analyze as analyze_tls
from backend.app.engines.certificate_transparency import analyze as analyze_ct
from backend.app.engines.certificate_risk import calculate as calculate_certificate_risk

def inspect_certificate(domain: str, revocation_db=None):
    report = collect(domain, revocation_db)
    report.setdefault("ct_records",[]); report.setdefault("evidence",[]); report.setdefault("unavailable",[])
    leaf=report.get("certificate",{})
    report["tls_configuration"] = analyze_tls(domain, leaf)
    if leaf:
        not_after=leaf.get("not_after")
        if leaf.get("public_key_algorithm") == "_RSAPublicKey" and leaf.get("public_key_size") and leaf["public_key_size"] < 2048: report["evidence"].append({"issue":"RSA public key is weaker than 2048 bits","severity":"high","impact":"Reduced cryptographic security","remediation":"Reissue with an RSA key of at least 2048 bits","limitation":"Assessment covers the leaf key only"})
    ct=analyze_ct(domain); report["ct_intelligence"]=ct; report["ct_records"]=[{"issuer_name":x.get("issuer"),"not_before":x.get("not_before"),"not_after":x.get("not_after"),"serial_number":x.get("serial_number"),"fingerprint_sha256":x.get("fingerprint_sha256")} for x in ct.get("records",[])[:50]]
    if ct.get("status") != "AVAILABLE": report["unavailable"].append(f"Certificate Transparency unavailable: {','.join(ct.get('errors',[])) or 'unknown_error'}")
    report["risk"] = calculate_certificate_risk(report)
    return report
