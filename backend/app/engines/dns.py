from datetime import datetime, timezone
import dns.resolver

def inspect_dns(domain: str):
    result = {"status":"available", "records":{}, "evidence":[], "unavailable":[], "checked_at":datetime.now(timezone.utc).isoformat(), "dnssec":"unknown"}
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            result["records"][kind] = [r.to_text() for r in dns.resolver.resolve(domain, kind, lifetime=3)]
        except Exception as exc:
            result["unavailable"].append(f"{kind}: {type(exc).__name__}")
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=3)
        result["dnssec"]="records_present"
    except Exception as exc:
        result["dnssec"]="unavailable"
        result["unavailable"].append(f"DNSKEY: {type(exc).__name__}")
    if not result["records"].get("A") and not result["records"].get("AAAA"):
        result["evidence"].append({"issue":"No address record returned","severity":"medium","impact":"Host may be inactive or DNS may be misconfigured","remediation":"Verify authoritative DNS records","limitation":"DNS answers vary by resolver and location"})
    return result
