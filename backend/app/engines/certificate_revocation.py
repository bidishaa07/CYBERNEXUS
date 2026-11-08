"""Cryptographic OCSP, CRL and CA trust intelligence.

Network failures are represented as unavailable/unknown results.  They are
never converted into GOOD.  Transport is performed through the pinned safe
HTTP helpers and all protocol responses are cryptographically checked before
being trusted.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.x509 import ocsp

from backend.app.engines.certificate_chain import _extension, _fingerprint, _verify_signature
from backend.app.engines.safe_http import SafeResponse, fetch as safe_fetch, post_binary, UnsafeDestination
from backend.app.core.config import settings
from backend.app.engines.ca_reputation import lookup as lookup_ca_reputation

MAX_REVOCATION_BYTES = 2 * 1024 * 1024
REVOCATION_TIMEOUT = 6.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value):
    return value.isoformat() if value else None


def _urls(cert: x509.Certificate, extension_type, scheme: str | None = None) -> list[str]:
    extension = _extension(cert, extension_type)
    values = []
    if extension_type is x509.AuthorityInformationAccess:
        for item in extension or []:
            if item.access_method == x509.AuthorityInformationAccessOID.OCSP:
                value = getattr(item.access_location, "value", "")
                values.append(value)
    else:
        for point in extension or []:
            for name in point.full_name or []:
                value = getattr(name, "value", "")
                values.append(value)
    result = []
    for value in values:
        parsed = urlsplit(value)
        if parsed.scheme in ({"http", "https"} if scheme is None else {scheme}) and parsed.hostname and not parsed.username and not parsed.password:
            result.append(value)
    return list(dict.fromkeys(result))


def _fetch_response(url: str, body: bytes | None = None, content_type: str = "") -> SafeResponse:
    if body is None:
        return safe_fetch(url, timeout=REVOCATION_TIMEOUT, max_bytes=MAX_REVOCATION_BYTES)
    return post_binary(url, body, content_type, timeout=REVOCATION_TIMEOUT, max_bytes=MAX_REVOCATION_BYTES)


def _verify_response_signature(response, issuer: x509.Certificate) -> tuple[bool, str]:
    """Verify OCSP signature and delegated responder authorization."""
    responders = list(response.certificates or [])
    responder = issuer
    delegated = False
    if response.responder_name is not None and response.responder_name != issuer.subject:
        responder = next((item for item in responders if item.subject == response.responder_name), None)
        delegated = responder is not None
    if responder is None:
        return False, "ocsp_responder_certificate_missing"
    try:
        public = responder.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), response.signature_hash_algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(response.signature_hash_algorithm))
        elif isinstance(public, dsa.DSAPublicKey):
            public.verify(response.signature, response.tbs_response_bytes, response.signature_hash_algorithm)
        else:
            return False, "ocsp_responder_key_unsupported"
    except Exception:
        return False, "ocsp_invalid_signature"
    if delegated:
        if responder.issuer != issuer.subject or not _verify_signature(responder, issuer):
            return False, "ocsp_responder_not_issued_by_certificate_issuer"
        eku = _extension(responder, x509.ExtendedKeyUsage)
        if not eku or x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            return False, "ocsp_responder_missing_ocsp_signing_eku"
    return True, "ocsp_signature_valid"


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, fetcher=None) -> dict:
    urls = _urls(cert, x509.AuthorityInformationAccess)
    result = {"source": "OCSP", "status": "UNAVAILABLE", "responder": urls[0] if urls else None, "checked_at": _iso(_now()), "evidence": [], "errors": []}
    if not urls:
        result["status"] = "UNAVAILABLE"
        result["errors"].append("ocsp_responder_not_advertised")
        return result
    nonce = secrets.token_bytes(16)
    try:
        builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
        try:
            builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
        except Exception:
            pass
        request = builder.build().public_bytes(serialization.Encoding.DER)
        get_response = fetcher or (lambda url, body: _fetch_response(url, body, "application/ocsp-request"))
        response = get_response(urls[0], request)
        if response.status_code != 200:
            result["errors"].append(f"http_{response.status_code}")
            result["status"] = "UNAVAILABLE"
            return result
        parsed = ocsp.load_der_ocsp_response(response.body)
        if parsed.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            result["errors"].append(f"ocsp_response_{parsed.response_status.name}")
            result["status"] = "INVALID_RESPONSE"
            return result
        if parsed.serial_number != cert.serial_number:
            result["errors"].append("ocsp_serial_mismatch")
            result["status"] = "INVALID_RESPONSE"
            return result
        signature_ok, signature_evidence = _verify_response_signature(parsed, issuer)
        result["evidence"].append(signature_evidence)
        if not signature_ok:
            result["status"] = "INVALID_RESPONSE"
            result["errors"].append(signature_evidence)
            return result
        now = _now()
        this_update = parsed.this_update_utc
        next_update = parsed.next_update_utc
        produced_at = parsed.produced_at_utc
        result.update({"this_update": _iso(this_update), "next_update": _iso(next_update), "produced_at": _iso(produced_at), "certificate_status": parsed.certificate_status.name})
        if this_update and this_update > now or next_update and next_update < now:
            result["status"] = "INVALID_RESPONSE"
            result["errors"].append("ocsp_response_stale_or_future")
            return result
        if parsed.certificate_status == ocsp.OCSPCertStatus.GOOD:
            result["status"] = "GOOD"
        elif parsed.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            result["status"] = "REVOKED"
            result["revocation_time"] = _iso(parsed.revocation_time_utc)
            result["revocation_reason"] = parsed.revocation_reason.name if parsed.revocation_reason else None
        else:
            result["status"] = "UNKNOWN"
        return result
    except (TimeoutError, OSError, UnsafeDestination) as exc:
        result["errors"].append(type(exc).__name__)
        return result
    except Exception as exc:
        result["errors"].append(type(exc).__name__)
        result["status"] = "INVALID_RESPONSE" if "response" in str(exc).lower() else "UNAVAILABLE"
        return result


def _verify_crl_signature(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> bool:
    try:
        public = issuer.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            public.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)
        elif isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(crl.signature, crl.tbs_certlist_bytes, ec.ECDSA(crl.signature_hash_algorithm))
        elif isinstance(public, dsa.DSAPublicKey):
            public.verify(crl.signature, crl.tbs_certlist_bytes, crl.signature_hash_algorithm)
        else:
            return False
        return True
    except Exception:
        return False


def check_crl(cert: x509.Certificate, issuer: x509.Certificate, fetcher=None) -> dict:
    urls = _urls(cert, x509.CRLDistributionPoints)
    result = {"source": "CRL", "status": "UNAVAILABLE", "crl_url": urls[0] if urls else None, "checked_at": _iso(_now()), "evidence": [], "errors": []}
    if not urls:
        result["errors"].append("crl_distribution_point_not_advertised")
        return result
    try:
        get_response = fetcher or (lambda url: _fetch_response(url))
        response = get_response(urls[0])
        if response.status_code != 200:
            result["errors"].append(f"http_{response.status_code}")
            return result
        try:
            crl = x509.load_der_x509_crl(response.body)
        except Exception:
            crl = x509.load_pem_x509_crl(response.body)
        if crl.issuer != issuer.subject:
            result["status"] = "INVALID_RESPONSE"
            result["errors"].append("crl_issuer_mismatch")
            return result
        if not _verify_crl_signature(crl, issuer):
            result["status"] = "INVALID_RESPONSE"
            result["errors"].append("crl_invalid_signature")
            return result
        now = _now()
        this_update = crl.last_update_utc
        next_update = crl.next_update_utc
        result.update({"issuer": crl.issuer.rfc4514_string(), "this_update": _iso(this_update), "next_update": _iso(next_update), "crl_number": str(_extension(crl, x509.CRLNumber).crl_number) if _extension(crl, x509.CRLNumber) else None})
        if this_update > now or next_update and next_update < now:
            result["status"] = "UNKNOWN"
            result["errors"].append("crl_expired_or_future")
            return result
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked:
            result["status"] = "REVOKED"
            result["revocation_date"] = _iso(revoked.revocation_date_utc)
            result["revocation_reason"] = _extension(revoked, x509.CRLReason).reason.name if _extension(revoked, x509.CRLReason) else None
        else:
            result["status"] = "GOOD"
            result["evidence"].append("certificate_serial_not_listed")
        return result
    except (TimeoutError, OSError, UnsafeDestination) as exc:
        result["errors"].append(type(exc).__name__)
        return result
    except Exception as exc:
        result["errors"].append(type(exc).__name__)
        result["status"] = "UNKNOWN"
        return result


def aggregate_revocation(ocsp_result: dict, crl_result: dict) -> dict:
    statuses = [ocsp_result.get("status"), crl_result.get("status")]
    if "REVOKED" in statuses:
        status = "REVOKED"
        explanation = "At least one cryptographically validated revocation source reports the certificate as revoked."
    elif statuses and all(item == "GOOD" for item in statuses):
        status = "GOOD"
        explanation = "All consulted revocation sources report that the certificate is not revoked."
    elif "GOOD" in statuses and "UNAVAILABLE" in statuses:
        status = "UNKNOWN"
        explanation = "At least one revocation source is unavailable, so a clean status cannot be established."
    elif "GOOD" in statuses and "UNKNOWN" in statuses:
        status = "UNKNOWN"
        explanation = "Revocation sources disagree or one source is indeterminate."
    elif "INVALID_RESPONSE" in statuses:
        status = "INVALID_RESPONSE"
        explanation = "A revocation response failed cryptographic or freshness validation."
    elif all(item == "UNAVAILABLE" for item in statuses):
        status = "UNAVAILABLE"
        explanation = "No revocation source was available."
    else:
        status = "UNKNOWN"
        explanation = "Revocation status could not be established."
    return {"status": status, "explanation": explanation, "sources": {"ocsp": ocsp_result, "crl": crl_result}, "checked_at": _iso(_now())}


def distrust_and_ca_intelligence(cert: x509.Certificate, trusted_roots: list[x509.Certificate], chain_role: str = "intermediate", db=None) -> dict:
    fingerprint = _fingerprint(cert)
    trust_anchor = any(cert.subject == root.subject and cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == root.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) for root in trusted_roots)
    advisory=lookup_ca_reputation(cert,trusted_roots,db)
    if advisory.get("status") in {"DISTRUSTED","COMPROMISED","REVOKED"}:
        advisory["role"]=chain_role
        return advisory
    advisory.update({"status":"TRUSTED_ANCHOR" if trust_anchor else advisory.get("status","NOT_TRUST_ANCHOR"),"fingerprint_sha256":fingerprint,"role":chain_role})
    if advisory.get("status")=="UNKNOWN" and trust_anchor:
        advisory["status"]="TRUSTED_ANCHOR"
    return advisory


def analyze_chain(certificates: list[tuple[x509.Certificate, bytes]], trusted_roots: list[x509.Certificate], db=None) -> dict:
    """Analyze leaf and every presented/discovered CA with independent sources."""
    results = []
    for index, (cert, _) in enumerate(certificates):
        issuer = certificates[index + 1][0] if index + 1 < len(certificates) and cert.issuer == certificates[index + 1][0].subject else next((root for root in trusted_roots if cert.issuer == root.subject and _verify_signature(cert, root)), None)
        if issuer is None:
            ocsp_result = {"source": "OCSP", "status": "UNAVAILABLE", "errors": ["issuer_unavailable"], "checked_at": _iso(_now())}
            crl_result = {"source": "CRL", "status": "UNAVAILABLE", "errors": ["issuer_unavailable"], "checked_at": _iso(_now())}
        else:
            fingerprint=_fingerprint(cert); issuer_fingerprint=_fingerprint(issuer); cached=None
            if db is not None:
                from backend.app.models.models import CertificateRevocationCache
                cached=db.query(CertificateRevocationCache).filter(CertificateRevocationCache.certificate_fingerprint==fingerprint,CertificateRevocationCache.issuer_fingerprint==issuer_fingerprint,CertificateRevocationCache.expires_at>_now()).first()
            if cached:
                cached_result=__import__("json").loads(cached.result_json)
                ocsp_result=cached_result["ocsp"]; crl_result=cached_result["crl"]
                ocsp_result["cache"]="hit"; crl_result["cache"]="hit"
            else:
                ocsp_result = check_ocsp(cert, issuer); crl_result = check_crl(cert, issuer)
                if db is not None:
                    from backend.app.models.models import CertificateRevocationCache
                    import json
                    from datetime import timedelta
                    cache_result=json.dumps({"ocsp":ocsp_result,"crl":crl_result})
                    row=db.query(CertificateRevocationCache).filter(CertificateRevocationCache.certificate_fingerprint==fingerprint,CertificateRevocationCache.issuer_fingerprint==issuer_fingerprint).first()
                    values={"result_json":cache_result,"checked_at":_now(),"expires_at":_now()+timedelta(seconds=settings.certificate_revocation_cache_ttl_seconds)}
                    if row:
                        for key,value in values.items(): setattr(row,key,value)
                    else: db.add(CertificateRevocationCache(certificate_fingerprint=fingerprint,issuer_fingerprint=issuer_fingerprint,**values))
        results.append({"fingerprint_sha256": _fingerprint(cert), "role": "leaf" if index == 0 else "intermediate", "aggregate": aggregate_revocation(ocsp_result, crl_result), "ca_trust": distrust_and_ca_intelligence(cert, trusted_roots, "leaf" if index == 0 else "intermediate", db)})
    return {"status": "REVOKED" if any(item["aggregate"]["status"] == "REVOKED" for item in results) else "UNKNOWN" if any(item["aggregate"]["status"] in {"UNKNOWN", "UNAVAILABLE", "INVALID_RESPONSE"} for item in results) else "GOOD", "certificates": results, "checked_at": _iso(_now()), "explanation": "Revocation evidence is independent from certificate path validity."}
