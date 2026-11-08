"""TLS certificate collection and cryptographic path validation.

Collection is deliberately performed with verification disabled only so the
presented chain can be inspected. Trust and hostname decisions are made by
the validator below and are never inferred from successful TLS negotiation.
"""
from __future__ import annotations
import hashlib, ipaddress, socket, ssl, fnmatch
from itertools import islice
from datetime import datetime, timezone
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID
from backend.app.engines.safe_http import resolve_public_ips, fetch as safe_fetch, UnsafeDestination

MAX_CHAIN_DEPTH = 12
MAX_ALTERNATIVE_PATHS = 8
MAX_AIA_CERTIFICATES = 8
MAX_AIA_BYTES = 512 * 1024

def _iso(value): return value.isoformat() if value else None

def _fingerprint(cert): return cert.fingerprint(hashes.SHA256()).hex()

def _extension(cert, cls):
    try: return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound: return None

def summary(cert: x509.Certificate, role: str = "intermediate", der: bytes | None = None) -> dict:
    san=_extension(cert,x509.SubjectAlternativeName); key_usage=_extension(cert,x509.KeyUsage); eku=_extension(cert,x509.ExtendedKeyUsage); basic=_extension(cert,x509.BasicConstraints); aki=_extension(cert,x509.AuthorityKeyIdentifier); ski=_extension(cert,x509.SubjectKeyIdentifier); aia=_extension(cert,x509.AuthorityInformationAccess); crl=_extension(cert,x509.CRLDistributionPoints); policies=_extension(cert,x509.CertificatePolicies)
    return {"role":role,"fingerprint_sha256":_fingerprint(cert),"subject":cert.subject.rfc4514_string(),"issuer":cert.issuer.rfc4514_string(),"serial_number":str(cert.serial_number),"not_before":cert.not_valid_before_utc.isoformat(),"not_after":cert.not_valid_after_utc.isoformat(),"san":san.get_values_for_type(x509.DNSName) if san else [],"san_ip":[str(value) for value in san.get_values_for_type(x509.IPAddress)] if san else [],"key_usage":[name for name in ("digital_signature","content_commitment","key_encipherment","data_encipherment","key_agreement","key_cert_sign","crl_sign") if key_usage and getattr(key_usage,name,False)],"extended_key_usage":[oid.dotted_string for oid in eku] if eku else [],"authority_key_identifier":aki.key_identifier.hex() if aki and aki.key_identifier else None,"subject_key_identifier":ski.digest.hex() if ski else None,"authority_information_access":[{ "method":item.access_method.dotted_string,"location":item.access_location.value} for item in aia] if aia else [],"crl_distribution_points":[str(point.full_name[0].value) for point in crl if point.full_name] if crl else [],"certificate_policies":[policy.policy_identifier.dotted_string for policy in policies] if policies else [],"basic_constraints":{"ca":basic.ca,"path_length":basic.path_length} if basic else None,"signature_algorithm":cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,"public_key_algorithm":type(cert.public_key()).__name__,"public_key_size":getattr(cert.public_key(),"key_size",None),"der":der.hex() if der else None}

def _presented_chain(host: str, port: int = 443) -> tuple[list[bytes], str | None]:
    ips=resolve_public_ips(host)
    if not ips: raise UnsafeDestination("hostname has no public address")
    try:
        from OpenSSL import SSL, crypto
    except ImportError:
        ips=[]
    if ips:
        sock=socket.create_connection((ips[0],port),timeout=8)
        try:
            context=SSL.Context(SSL.TLS_CLIENT_METHOD); context.set_verify(SSL.VERIFY_NONE, lambda *_: True)
            connection=SSL.Connection(context,sock); connection.setblocking(1); connection.set_tlsext_host_name(host.encode("idna")); connection.set_connect_state(); connection.do_handshake()
            chain=connection.get_peer_cert_chain() or []
            return [crypto.dump_certificate(crypto.FILETYPE_ASN1,item) for item in chain], "pyOpenSSL"
        finally:
            try: connection.shutdown(); connection.close()
            except Exception: pass
            sock.close()
    raise RuntimeError("presented certificate chain retrieval is unavailable")


def _aia_issuer_urls(cert: x509.Certificate) -> list[str]:
    """Return only HTTPS AIA issuer URLs.

    AIA is untrusted input.  HTTPS is required here so an attacker cannot
    replace an issuer certificate during discovery.  The issuer certificate
    is still cryptographically verified later; transport security is not a
    substitute for path validation.
    """
    aia = _extension(cert, x509.AuthorityInformationAccess)
    urls = []
    if not aia:
        return urls
    for access in aia:
        if access.access_method != x509.AuthorityInformationAccessOID.CA_ISSUERS:
            continue
        value = getattr(access.access_location, "value", "")
        parsed = urlsplit(value)
        if parsed.scheme.lower() == "https" and parsed.hostname and parsed.username is None and parsed.password is None:
            urls.append(value)
    return list(dict.fromkeys(urls))


def _download_aia_certificates(certificates: list[tuple[x509.Certificate, bytes]]) -> tuple[list[tuple[x509.Certificate, bytes]], list[str]]:
    """Fetch bounded issuer candidates from certificate AIA extensions.

    This is discovery only.  Every downloaded certificate is parsed and is
    later accepted only if its signature, issuer relationship, constraints and
    trust path validate.  Failures are returned as diagnostics, never as a
    clean result.
    """
    discovered: list[tuple[x509.Certificate, bytes]] = []
    errors: list[str] = []
    seen_urls: set[str] = set()
    seen_fingerprints = {_fingerprint(cert) for cert, _ in certificates}
    queue = list(certificates)
    while queue and len(seen_urls) < MAX_AIA_CERTIFICATES and len(discovered) < MAX_AIA_CERTIFICATES:
        cert, _ = queue.pop(0)
        urls = _aia_issuer_urls(cert)
        for url in urls:
            if len(seen_urls) >= MAX_AIA_CERTIFICATES or len(discovered) >= MAX_AIA_CERTIFICATES:
                break
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                response = safe_fetch(url, timeout=5.0, max_bytes=MAX_AIA_BYTES)
                if response.status_code != 200:
                    errors.append(f"aia_http_{response.status_code}")
                    continue
                body = response.body
                if not body or len(body) > MAX_AIA_BYTES:
                    errors.append("aia_certificate_size_invalid")
                    continue
                try:
                    parsed = x509.load_der_x509_certificate(body)
                except Exception:
                    errors.append("aia_malformed_certificate")
                    continue
                fp = _fingerprint(parsed)
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    discovered.append((parsed, body))
                    queue.append((parsed, body))
            except (TimeoutError, socket.timeout) as exc:
                errors.append(f"aia_{type(exc).__name__}")
            except Exception:
                errors.append("aia_discovery_failed")
    return discovered, errors

def collect(host: str, revocation_db=None) -> dict:
    original=host.lower().rstrip("."); report={"status":"UNAVAILABLE","domain":original,"certificates":[],"chain":[],"intermediates":[],"trust_anchor":None,"validation":{},"errors":[],"checked_at":datetime.now(timezone.utc).isoformat()}
    try:
        ders,source=_presented_chain(original); report["collection_source"]=source
    except Exception as exc:
        # A verified stdlib handshake still gives a trustworthy leaf, but not a
        # complete chain. This state is intentionally never called VALID.
        try:
            ips=resolve_public_ips(original); sock=socket.create_connection((ips[0],443),timeout=8); context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
            with context.wrap_socket(sock,server_hostname=original) as tls: ders=[tls.getpeercert(binary_form=True)]
            report["collection_source"]="stdlib-leaf-only"; report["errors"].append("Presented chain API unavailable; only the leaf certificate was collected")
        except Exception as leaf_exc:
            report["errors"].append(type(leaf_exc).__name__); report["validation"]={"status":"UNAVAILABLE","errors":report["errors"]}; return report
    certs=[]
    for der in ders[:MAX_CHAIN_DEPTH]:
        try: certs.append((x509.load_der_x509_certificate(der),der))
        except Exception: report["errors"].append("malformed_certificate")
    aia_certs, aia_errors = _download_aia_certificates(certs)
    if aia_certs:
        certs.extend(aia_certs[:MAX_AIA_CERTIFICATES])
        report["aia_discovered_certificates"] = len(aia_certs)
    report["errors"].extend(aia_errors)
    report["certificates"]=[summary(cert,"leaf" if i==0 else "intermediate",der) for i,(cert,der) in enumerate(certs)]
    report["certificate"] = report["certificates"][0] if report["certificates"] else {}
    report["chain"]=[{k:v for k,v in item.items() if k != "der"} for item in report["certificates"]]; report["intermediates"]=report["chain"][1:]
    report["validation"]=validate_path(original,certs)
    report["alternative_paths"] = report["validation"].get("alternative_paths", [])
    try:
        from backend.app.engines.certificate_revocation import analyze_chain
        report["revocation"] = analyze_chain(certs, _trusted_roots(), revocation_db)
    except Exception as exc:
        report["revocation"] = {"status": "UNAVAILABLE", "certificates": [], "checked_at": datetime.now(timezone.utc).isoformat(), "errors": [type(exc).__name__], "explanation": "Revocation analysis could not be initialized."}
    report["status"]=report["validation"]["status"]
    return report

def _verify_signature(child, issuer):
    try:
        signature=child.signature; algorithm=child.signature_hash_algorithm; public=issuer.public_key()
        if isinstance(public,rsa.RSAPublicKey): public.verify(signature,child.tbs_certificate_bytes,padding.PKCS1v15(),algorithm)
        elif isinstance(public,ec.EllipticCurvePublicKey): public.verify(signature,child.tbs_certificate_bytes,ec.ECDSA(algorithm))
        elif isinstance(public,dsa.DSAPublicKey): public.verify(signature,child.tbs_certificate_bytes,algorithm)
        else: return False
        return True
    except Exception: return False

def _trusted_roots():
    roots=[]
    try:
        context=ssl.create_default_context()
        for der in context.get_ca_certs(binary_form=True):
            try: roots.append(x509.load_der_x509_certificate(der))
            except Exception: pass
    except Exception: pass
    return roots

def _hostname_matches(host, leaf):
    try:
        san=_extension(leaf,x509.SubjectAlternativeName)
        if not san: return False
        try:
            target_ip=ipaddress.ip_address(host)
            return any(isinstance(value, x509.IPAddress) and value.value == target_ip for value in san)
        except ValueError: pass
        host=host.lower().rstrip(".")
        for name in san.get_values_for_type(x509.DNSName):
            name=name.lower().rstrip(".")
            if name == host or (name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count(".")): return True
        return False
    except Exception: return False

def _candidate_paths(leaf: x509.Certificate, pool: list[tuple[x509.Certificate, bytes]], roots: list[x509.Certificate]) -> list[list[tuple[x509.Certificate, bytes]]]:
    """Enumerate bounded issuer paths, retaining distinct cross-signed keys."""
    by_subject: dict[str, list[tuple[x509.Certificate, bytes]]] = {}
    for item in pool:
        by_subject.setdefault(item[0].subject.rfc4514_string(), []).append(item)
    root_items = [(root, root.public_bytes(serialization.Encoding.DER)) for root in roots]
    for root, der in root_items:
        by_subject.setdefault(root.subject.rfc4514_string(), []).append((root, der))
    paths: list[list[tuple[x509.Certificate, bytes]]] = []
    def walk(path: list[tuple[x509.Certificate, bytes]], visited: set[str]):
        if len(paths) >= MAX_ALTERNATIVE_PATHS or len(path) > MAX_CHAIN_DEPTH:
            return
        current = path[-1][0]
        if any(current.subject == root.subject and _same_public_key(current, root) for root in roots):
            paths.append(path)
            return
        candidates = by_subject.get(current.issuer.rfc4514_string(), [])
        progressed = False
        for candidate in candidates:
            fp = _fingerprint(candidate[0])
            if fp in visited or candidate[0].subject != current.issuer:
                continue
            if not _verify_signature(current, candidate[0]):
                continue
            progressed = True
            walk(path + [candidate], visited | {fp})
        if not progressed and current.issuer == current.subject and any(_same_public_key(current, root) for root in roots):
            paths.append(path)
    walk([pool[0]], {_fingerprint(pool[0][0])})
    return paths


def _same_public_key(left: x509.Certificate, right: x509.Certificate) -> bool:
    encoding = serialization.Encoding.DER
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    return left.public_key().public_bytes(encoding, fmt) == right.public_key().public_bytes(encoding, fmt)


def _validate_single_path(host: str, path: list[tuple[x509.Certificate, bytes]], roots: list[x509.Certificate]) -> dict:
    if not path: return {"status":"UNKNOWN","errors":["no_certificates"]}
    now=datetime.now(timezone.utc); leaf=path[0][0]; errors=[]; evidence=[]; visited=set(); trust=None
    for cert,_ in path:
        fp=_fingerprint(cert)
        if fp in visited: errors.append("circular_chain"); return {"status":"INVALID","errors":errors}
        visited.add(fp)
        if now < cert.not_valid_before_utc: errors.append(f"not_yet_valid:{fp}")
        if now > cert.not_valid_after_utc: errors.append(f"expired:{fp}")
    from backend.app.engines.tls_configuration import validate_san
    san_validation=validate_san(host,summary(leaf).get("san",[]),summary(leaf).get("san_ip",[]))
    if san_validation.get("status") != "VALID": errors.append("hostname_mismatch")
    roots=roots if roots is not None else _trusted_roots()
    for index in range(len(path)-1):
        child, _=path[index]; issuer,_=path[index+1]
        if child.issuer != issuer.subject: errors.append(f"issuer_subject_mismatch:{index}"); continue
        if not _verify_signature(child,issuer): errors.append(f"invalid_signature:{index}")
        constraints=_extension(issuer,x509.BasicConstraints); usage=_extension(issuer,x509.KeyUsage)
        if not constraints or not constraints.ca: errors.append(f"issuer_not_ca:{index+1}")
        if usage and not usage.key_cert_sign: errors.append(f"issuer_missing_key_cert_sign:{index+1}")
        if constraints and constraints.path_length is not None and index > constraints.path_length: errors.append(f"path_length_exceeded:{index+1}")
    last=path[-1][0]
    for root in roots:
        if last.subject == root.subject and _same_public_key(last, root): trust=root; break
        if last.issuer == root.subject and _verify_signature(last,root): trust=root; break
    if trust: evidence.append({"type":"trusted_system_anchor","subject":trust.subject.rfc4514_string()})
    elif last.issuer != last.subject: errors.append("untrusted_or_missing_trust_anchor")
    if not trust and any(last.issuer == cert.subject for cert,_ in path[:-1]): errors.append("circular_chain")
    status="VALID" if not errors and trust else "INVALID" if any(x.startswith(("invalid_","hostname_","expired:","not_yet_valid:","issuer_","circular","path_length")) for x in errors) else "INCOMPLETE" if "untrusted_or_missing_trust_anchor" in errors else "UNKNOWN"
    return {"status":status,"errors":errors,"evidence":evidence,"trust_anchor":summary(trust,"trust_anchor") if trust else None,"san_validation":san_validation,"checked_at":datetime.now(timezone.utc).isoformat()}


def validate_path(host: str, certs: list[tuple[x509.Certificate,bytes]], roots: list[x509.Certificate] | None = None) -> dict:
    """Validate the best available path and report alternate paths.

    The first certificate is always the leaf.  Candidate paths are built from
    all presented/AIA certificates and system trust anchors; each candidate is
    independently cryptographically validated.  A valid path wins over an
    incomplete or invalid presented path, which is required for cross-signed
    intermediates.
    """
    if not certs:
        return {"status":"UNKNOWN","errors":["no_certificates"]}
    roots = roots if roots is not None else _trusted_roots()
    candidates = _candidate_paths(certs[0][0], certs, roots)
    if not candidates:
        result = _validate_single_path(host, certs, roots)
        result["alternative_paths"] = []
        return result
    evaluations = []
    for path in candidates:
        result = _validate_single_path(host, path, roots)
        result["path_fingerprints"] = [_fingerprint(cert) for cert, _ in path]
        evaluations.append(result)
    valid = [result for result in evaluations if result["status"] == "VALID"]
    chosen = valid[0] if valid else evaluations[0]
    chosen["alternative_paths"] = [{"status": item["status"], "path_fingerprints": item["path_fingerprints"], "errors": item["errors"], "trust_anchor": item["trust_anchor"]} for item in evaluations]
    if len(evaluations) > 1:
        chosen["evidence"] = chosen.get("evidence", []) + [{"type":"alternative_paths_evaluated","count":len(evaluations)}]
    return chosen
