"""Actual TLS protocol/cipher probing and explainable security grading."""
from __future__ import annotations
import ipaddress, socket, ssl
from datetime import datetime, timezone
from backend.app.core.config import settings
from backend.app.engines.safe_http import resolve_public_ips, UnsafeDestination

TLS_VERSIONS = (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)

def _now(): return datetime.now(timezone.utc).isoformat()

def validate_san(host: str, san_entries: list[str] | None, san_ip_entries: list[str] | None = None) -> dict:
    requested=host.rstrip(".").lower(); entries=list(san_entries or []); ip_entries=list(san_ip_entries or [])
    if not entries and not ip_entries:
        return {"status":"MISSING_SAN","requested_hostname":host,"san_entries":[],"matched_entry":None,"errors":["subject_alternative_name_missing"],"explanation":"Modern hostname validation requires a matching Subject Alternative Name; Common Name is not used as a fallback."}
    try:
        requested_ip=ipaddress.ip_address(requested)
    except ValueError:
        requested_ip=None
    if requested_ip is not None:
        for item in ip_entries:
            try:
                if ipaddress.ip_address(item) == requested_ip:
                    return {"status":"VALID","requested_hostname":host,"san_entries":entries,"san_ip_entries":ip_entries,"matched_entry":item,"errors":[],"explanation":"The requested IP exactly matches an IP Subject Alternative Name."}
            except ValueError:
                continue
        return {"status":"MISMATCH","requested_hostname":host,"san_entries":entries,"san_ip_entries":ip_entries,"matched_entry":None,"errors":["ip_san_mismatch"],"explanation":"The requested IP does not match any IP Subject Alternative Name."}
    try:
        normalized=requested.encode("idna").decode("ascii")
    except UnicodeError:
        normalized=requested
    for raw in entries:
        name=raw.rstrip(".").lower()
        try: name=name.encode("idna").decode("ascii")
        except UnicodeError: pass
        if "*" in name:
            valid_wildcard=name.startswith("*.") and name.count("*")==1 and name[2:].find("*")==-1 and name.count(".")>=1
            if valid_wildcard and normalized.endswith(name[1:]) and normalized.count(".")==name.count("."):
                return {"status":"VALID","requested_hostname":host,"san_entries":entries,"san_ip_entries":ip_entries,"matched_entry":raw,"errors":[],"explanation":"The hostname matches a valid left-most wildcard SAN for one label."}
            continue
        if name==normalized:
            return {"status":"VALID","requested_hostname":host,"san_entries":entries,"san_ip_entries":ip_entries,"matched_entry":raw,"errors":[],"explanation":"The hostname exactly matches a DNS Subject Alternative Name."}
    return {"status":"MISMATCH","requested_hostname":host,"san_entries":entries,"san_ip_entries":ip_entries,"matched_entry":None,"errors":["dns_san_mismatch"],"explanation":"The requested hostname does not match any DNS Subject Alternative Name."}

def _handshake(host: str, version: ssl.TLSVersion) -> dict:
    ips=resolve_public_ips(host)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.minimum_version=version; context.maximum_version=version; context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
    sock=socket.create_connection((ips[0],443),timeout=settings.tls_grading_timeout_seconds)
    try:
        with context.wrap_socket(sock,server_hostname=host) as tls:
            cipher=tls.cipher() or (None,None,None)
            return {"status":"SUPPORTED","version":tls.version(),"cipher_name":cipher[0],"cipher_protocol":cipher[1],"cipher_bits":cipher[2],"ip":ips[0]}
    finally:
        sock.close()

def grade_cipher(cipher_name: str | None, protocol: str | None, bits: int | None) -> dict:
    if not cipher_name:
        return {"grade":"UNKNOWN","status":"UNKNOWN","evidence":[],"explanation":"No negotiated cipher was available."}
    upper=cipher_name.upper(); evidence=[]
    aead=any(token in upper for token in ("GCM","CHACHA20_POLY1305","CCM")); fs=any(token in upper for token in ("ECDHE","DHE","TLS_AES","CHACHA20")); weak=any(token in upper for token in ("RC4","3DES","DES-CBC","NULL","EXPORT","MD5")) or ("SHA1" in upper and "TLS_AES" not in upper)
    key_exchange="ECDHE" if "ECDHE" in upper else "DHE" if "DHE" in upper else "RSA" if "RSA" in upper else "TLS 1.3 negotiated" if protocol=="TLSv1.3" else "Unknown"
    if weak: grade="F"; evidence.append("deprecated_or_weak_cipher_pattern")
    elif aead and fs and (bits or 0)>=settings.tls_minimum_cipher_bits: grade="A"; evidence.extend(["AEAD cipher","forward secrecy",f"at least {settings.tls_minimum_cipher_bits}-bit negotiated strength"])
    elif aead and (bits or 0)>=settings.tls_minimum_cipher_bits: grade="B"; evidence.append("AEAD cipher without confirmed modern key exchange")
    else: grade="C"; evidence.append("cipher does not meet the preferred AEAD/forward-secrecy policy")
    return {"grade":grade,"status":"ANALYZED","cipher_name":cipher_name,"protocol":protocol,"encryption_bits":bits,"encryption_algorithm":"ChaCha20-Poly1305" if "CHACHA20" in upper else "AES-GCM" if "GCM" in upper else "Unknown","key_exchange":key_exchange,"forward_secrecy":fs,"aead":aead,"evidence":evidence,"explanation":"Cipher grading uses negotiated properties and configurable modern-cryptography policy."}

def grade_tls_versions(handshakes: list[dict]) -> dict:
    supported=[item["version"] for item in handshakes if item.get("status")=="SUPPORTED"]
    deprecated=[item for item in supported if item in {"TLSv1","TLSv1.0","TLSv1.1"}]
    if not supported: grade="UNKNOWN"; status="UNAVAILABLE"; explanation="No TLS protocol version could be negotiated."
    elif deprecated: grade="C"; status="ANALYZED"; explanation="Deprecated TLS 1.0/1.1 support was observed."
    elif any(item=="TLSv1.3" for item in supported) and settings.tls_minimum_version in {"TLSv1.2","TLSv1.3"}: grade="A"; status="ANALYZED"; explanation=f"TLS 1.3 is supported under the configured minimum policy ({settings.tls_minimum_version})."
    else: grade="B"; status="ANALYZED"; explanation="TLS 1.2 is supported but TLS 1.3 was not observed."
    return {"grade":grade,"status":status,"supported_versions":supported,"deprecated_versions":deprecated,"evidence":deprecated or supported,"explanation":explanation}

def grade_certificate_algorithm(leaf: dict) -> dict:
    algorithm=str(leaf.get("public_key_algorithm") or ""); size=leaf.get("public_key_size") or 0; signature=str(leaf.get("signature_algorithm") or "").lower(); evidence=[]
    if "RSA" in algorithm.upper(): grade="A" if size>=2048 else "F"; evidence.append(f"RSA {size}-bit public key")
    elif "EC" in algorithm or "Elliptic" in algorithm: grade="A" if size>=224 else "B"; evidence.append(f"elliptic-curve public key ({size} bits)")
    elif algorithm: grade="B"; evidence.append(algorithm)
    else: return {"grade":"UNKNOWN","status":"UNKNOWN","evidence":[],"explanation":"Certificate public-key algorithm was unavailable."}
    if any(token in signature for token in ("md5","sha1")): grade="F"; evidence.append("deprecated certificate signature hash")
    return {"grade":grade,"status":"ANALYZED","evidence":evidence,"signature_algorithm":leaf.get("signature_algorithm"),"explanation":"Certificate algorithm grading is separate from protocol and cipher negotiation."}

def analyze(host: str, leaf: dict | None = None) -> dict:
    handshakes=[]; failures=[]
    for version in TLS_VERSIONS:
        label={ssl.TLSVersion.TLSv1:"TLSv1.0",ssl.TLSVersion.TLSv1_1:"TLSv1.1",ssl.TLSVersion.TLSv1_2:"TLSv1.2",ssl.TLSVersion.TLSv1_3:"TLSv1.3"}[version]
        try:
            result=_handshake(host,version); result["requested_version"]=label; handshakes.append(result)
        except Exception as exc:
            failures.append({"version":label,"status":"UNSUPPORTED_OR_FAILED","error":type(exc).__name__})
    versions=grade_tls_versions(handshakes); negotiated=next((item for item in handshakes if item.get("version")=="TLSv1.3"),handshakes[-1] if handshakes else None)
    cipher=grade_cipher(negotiated.get("cipher_name") if negotiated else None,negotiated.get("version") if negotiated else None,negotiated.get("cipher_bits") if negotiated else None)
    cert_grade=grade_certificate_algorithm(leaf or {})
    san=validate_san(host,list((leaf or {}).get("san") or []),list((leaf or {}).get("san_ip") or []))
    overall="UNKNOWN" if versions["grade"]=="UNKNOWN" or cipher["grade"]=="UNKNOWN" else "F" if "F" in {versions["grade"],cipher["grade"],cert_grade["grade"]} or san["status"]!="VALID" else "A" if versions["grade"]==cipher["grade"]==cert_grade["grade"]=="A" else "B"
    return {"status":"ANALYZED" if handshakes else "UNAVAILABLE","checked_at":_now(),"version_security":versions,"cipher_security":cipher,"certificate_algorithm_security":cert_grade,"san_validation":san,"handshakes":handshakes,"failed_negotiations":failures,"negotiated":negotiated,"overall_grade":overall,"explanation":"TLS configuration grades are based on actual version-specific handshakes and certificate evidence; they do not establish website safety."}
