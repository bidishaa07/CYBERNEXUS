"""Independent, explainable certificate risk scoring.

Default weights are documented here and can be overridden with
CERTIFICATE_RISK_WEIGHTS_JSON.  Unknown/unavailable evidence never adds risk
and never becomes a clean finding. Related findings are deduplicated by key.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from backend.app.core.config import settings

DEFAULT_WEIGHTS={
    "invalid_chain":35,"untrusted_root":25,"expired":30,"not_yet_valid":30,
    "revoked":70,"ocsp_invalid":35,"crl_invalid":35,"distrusted_ca":75,
    "compromised_ca":75,"weak_public_key":25,"weak_signature":25,
    "deprecated_tls":20,"weak_cipher":25,"san_mismatch":45,
    "ct_high_anomaly":20,"ct_low_anomaly":5,
}

def weights():
    try:
        override=json.loads(getattr(settings,"certificate_risk_weights_json","{}") or "{}")
        return {**DEFAULT_WEIGHTS,**{key:int(value) for key,value in override.items() if key in DEFAULT_WEIGHTS and int(value)>=0}}
    except (TypeError,ValueError,json.JSONDecodeError): return dict(DEFAULT_WEIGHTS)

def _finding(key,kind,points,confidence,source,evidence,explanation):
    return {"key":key,"finding_type":kind,"points":points,"confidence":confidence,"source":source,"evidence":evidence,"explanation":explanation,"checked_at":datetime.now(timezone.utc).isoformat()}

def calculate(certificate: dict | None) -> dict:
    certificate=certificate or {}; validation=certificate.get("validation") or {}; revocation=certificate.get("revocation") or {}; tls=certificate.get("tls_configuration") or {}; ct=certificate.get("ct_intelligence") or {}; w=weights(); findings=[]; seen=set()
    def add(key,kind,weight,confidence,source,evidence,explanation):
        if key in seen or not weight: return
        seen.add(key); findings.append(_finding(key,kind,weight,confidence,source,evidence,explanation))
    errors=set(validation.get("errors") or [])
    if validation.get("status") in {"INVALID"}: add("chain_invalid","invalid_chain",w["invalid_chain"],"high","certificate_path",validation,"Certificate path validation failed; TLS negotiation alone cannot establish trust.")
    if any("untrusted_or_missing_trust_anchor" in item for item in errors): add("untrusted_root","untrusted_root",w["untrusted_root"],"high","certificate_path",list(errors),"No trusted system anchor was established for the selected certificate path.")
    if any(item.startswith("expired:") for item in errors): add("certificate_expired","expired",w["expired"],"high","certificate_path",list(errors),"A certificate in the selected path is expired.")
    if any(item.startswith("not_yet_valid:") for item in errors): add("certificate_not_yet_valid","not_yet_valid",w["not_yet_valid"],"high","certificate_path",list(errors),"A certificate in the selected path is not yet valid.")
    rev_status=revocation.get("status")
    if rev_status=="REVOKED": add("revoked","revoked",w["revoked"],"high","OCSP/CRL",revocation,"At least one validated revocation source reports a revoked certificate.")
    for item in revocation.get("certificates",[]):
        aggregate=item.get("aggregate",{}); sources=aggregate.get("sources",{}); ca=item.get("ca_trust",{})
        if aggregate.get("status")=="INVALID_RESPONSE": add(f"revocation_invalid:{item.get('fingerprint_sha256')}","revocation_response_invalid",max(w["ocsp_invalid"],w["crl_invalid"]),"medium","OCSP/CRL",item,"A revocation response failed cryptographic or freshness validation.")
        if ca.get("status") in {"DISTRUSTED","COMPROMISED","REVOKED"} or ca.get("ca_reputation") in {"COMPROMISED","COMPROMISED_OR_DISTRUSTED","DISTRUSTED","REVOKED"}:
            add(f"ca:{item.get('fingerprint_sha256')}","distrusted_or_compromised_ca",w["distrusted_ca"],"high",ca.get("source","CA trust"),ca,"The CA certificate has explicit distrust or compromise evidence.")
    cert_grade=(tls.get("certificate_algorithm_security") or {}).get("grade")
    leaf=certificate.get("certificate") or {}
    if cert_grade=="F" or (leaf.get("public_key_size") and leaf.get("public_key_size")<2048): add("weak_public_key","weak_public_key",w["weak_public_key"],"high","certificate_algorithm_security",tls.get("certificate_algorithm_security"),"The certificate uses a public key below the configured strength policy.")
    if any(token in str(leaf.get("signature_algorithm","")).lower() for token in ("sha1","md5")): add("weak_signature","weak_signature",w["weak_signature"],"high","certificate_metadata",leaf.get("signature_algorithm"),"The certificate signature uses a deprecated hash algorithm.")
    version=(tls.get("version_security") or {})
    if version.get("deprecated_versions"): add("deprecated_tls","deprecated_tls",w["deprecated_tls"],"high","TLS handshake",version,"Deprecated TLS protocol support was observed in actual handshakes.")
    cipher=(tls.get("cipher_security") or {})
    if cipher.get("grade") in {"C","F"}: add("weak_cipher","weak_cipher",w["weak_cipher"],"medium","TLS handshake",cipher,"The negotiated cipher does not meet the configured modern cipher policy.")
    san=(tls.get("san_validation") or validation.get("san_validation") or {})
    if san.get("status") in {"MISMATCH","MISSING_SAN"}: add("san_mismatch","san_hostname_mismatch",w["san_mismatch"],"high","SAN validation",san,"The requested hostname is not established by a valid Subject Alternative Name.")
    for anomaly in ct.get("anomalies",[]):
        severity="high" if anomaly.get("finding_type")=="distrusted_or_compromised_ca" or anomaly.get("confidence")=="high" else "low"
        add(f"ct:{anomaly.get('finding_type')}:{anomaly.get('fingerprint')}","ct_anomaly",w["ct_high_anomaly"] if severity=="high" else w["ct_low_anomaly"],"high" if severity=="high" else "low","Certificate Transparency",anomaly,anomaly.get("explanation","CT anomaly observed."))
    score=min(100,sum(item["points"] for item in findings)); level="Critical" if score>=80 else "High" if score>=55 else "Medium" if score>=25 else "Low" if score>0 else "Informational"
    confidence="High" if any(item["confidence"]=="high" for item in findings) else "Medium" if findings else "Low"
    return {"score":score,"level":level,"confidence":confidence,"validation_status":validation.get("status","UNKNOWN"),"tls_grade":tls.get("overall_grade","UNKNOWN"),"revocation_status":revocation.get("status","UNKNOWN"),"ca_trust_status":next((item.get("ca_trust",{}).get("status") for item in revocation.get("certificates",[]) if item.get("ca_trust")),"UNKNOWN"),"ct_anomaly_score":sum(item["points"] for item in findings if item["source"]=="Certificate Transparency"),"findings":findings,"explanation":"Certificate risk is independently scored from cryptographic validation, revocation, TLS, SAN and CT evidence. Unknown or unavailable evidence is not treated as safe or malicious.","model":"weighted evidence v1","weights":w,"checked_at":datetime.now(timezone.utc).isoformat()}
