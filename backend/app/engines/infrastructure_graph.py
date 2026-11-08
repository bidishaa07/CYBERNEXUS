from datetime import datetime, timezone

def build_graph(domain, intel, findings=None, related=None, limit=100):
    nodes=[]; edges=[]; node_ids=set(); edge_ids=set(); now=datetime.now(timezone.utc).isoformat(); findings=findings or []
    def node(node_id, kind, label, data=None):
        if node_id not in node_ids and len(nodes)<limit:
            node_ids.add(node_id); nodes.append({"id":node_id,"type":kind,"label":label,"data":data or {}})
        return node_id
    def edge(source, target, relation, evidence, confidence="medium"):
        key=(source,target,relation)
        if key not in edge_ids and len(edges)<limit*2:
            edge_ids.add(key); edges.append({"id":f"{source}:{target}:{relation}","source":source,"target":target,"relationship":relation,"evidence":evidence,"observed_at":now,"confidence":confidence,"description":evidence})
    domain_id=node(f"domain:{domain}","domain",domain,{"registered_domain":(intel.get("domain") or {}).get("registered_domain")})
    infrastructure=intel.get("infrastructure") or {}; rdap=intel.get("rdap") or {}; d=(intel.get("domain") or {})
    for ip in infrastructure.get("ips",[]):
        ip_id=node(f"ip:{ip}","ipv6" if ":" in ip else "ipv4",ip); edge(domain_id,ip_id,"resolves_to","DNS resolution", "high")
    for ns in rdap.get("nameservers",[]):
        ns_id=node(f"nameserver:{ns}","nameserver",ns); edge(domain_id,ns_id,"uses_nameserver","RDAP nameserver data", "high")
    for item in infrastructure.get("providers",[]):
        ip=item.get("ip"); asn=item.get("asn_number"); org=item.get("asn_organization")
        if ip and asn:
            ip_id=node(f"ip:{ip}","ipv6" if ":" in ip else "ipv4",ip); asn_id=node(f"asn:{asn}","asn",asn,{"organization":org}); edge(ip_id,asn_id,"belongs_to_asn","IP intelligence provider result", "high")
        if asn and org:
            asn_id=node(f"asn:{asn}","asn",asn); org_id=node(f"org:{org.lower()}","hosting_organization",org); edge(asn_id,org_id,"announced_by","IP intelligence ASN organization", "medium")
    for finding in findings:
        provider=finding.get("provider","unknown"); indicator=finding.get("reference") or provider; tid=node(f"threat:{provider}:{indicator}","threat_indicator",str(indicator),finding); edge(domain_id,tid,"has_threat_indicator",f"Finding from {provider}","high" if finding.get("state")=="confirmed" else "medium")
    if d.get("ownership",{}).get("status")=="verified":
        official=d["ownership"].get("official_domain"); brand=d["ownership"].get("brand")
        if official: bid=node(f"brand:{official}","verified_brand",brand or official,{"official_domain":official}); edge(domain_id,bid,"verified_brand_domain",d["ownership"].get("source","registry"),"high")
    for item in (related or [])[:20]:
        related_domain=item.get("domain")
        if related_domain and related_domain != domain:
            rid=node(f"domain:{related_domain}","related_domain",related_domain); edge(domain_id,rid,item.get("relationship","shared_infrastructure"),item.get("evidence","Historical infrastructure comparison"),"low")
    return {"nodes":nodes,"edges":edges,"truncated":len(nodes)>=limit or len(edges)>=limit*2,"generated_at":now,"limits":{"max_nodes":limit,"max_edges":limit*2}}
