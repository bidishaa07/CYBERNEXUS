def calculate(phishing, network, threats, domain_intelligence=None, certificate=None):
    score = phishing["score"]
    contributions = []
    if phishing.get("evidence"): contributions.append({"source":"phishing","points":min(35, phishing["score"]),"explanation":"URL and domain phishing signals were detected."})
    score += min(20, sum(5 for x in network.get("evidence", []) if x.get("severity") == "high"))
    score += min(35, 35 if threats.get("findings") else 0)
    if domain_intelligence:
        brand_points=min(20, len(domain_intelligence.get("domain",{}).get("brand_matches",[]))*10)
        indicator_points=min(10, len(domain_intelligence.get("domain",{}).get("indicators",[]))*5)
        score += brand_points + indicator_points
        if brand_points: contributions.append({"source":"domain_similarity","points":brand_points,"explanation":"Configured brand-domain similarity requires review; similarity is not proof of fraud."})
        if indicator_points: contributions.append({"source":"domain_indicators","points":indicator_points,"explanation":"Suspicious domain indicators were observed."})
        for match in (domain_intelligence.get("identity",{}).get("logo_comparisons",[]) if isinstance(domain_intelligence.get("identity",{}).get("logo_comparisons"),list) else []):
            if match.get("similarity_percent",0) >= 92 and match.get("official_domain") != domain_intelligence.get("domain",{}).get("registered_domain"):
                score += 5; contributions.append({"source":"logo_similarity","points":5,"explanation":"A high-similarity approved logo was found on a domain without verified ownership; this is an identity mismatch signal, not proof of fraud."}); break
        identity_findings=domain_intelligence.get("identity",{}).get("findings",[])
        if isinstance(identity_findings,list):
            seen_brands=set()
            for finding in identity_findings:
                brand=finding.get("brand")
                if not brand or brand in seen_brands or finding.get("finding_type") != "favicon_reference_match": continue
                seen_brands.add(brand)
                if domain_intelligence.get("domain",{}).get("ownership",{}).get("status") != "verified" and (finding.get("exact_match") or (finding.get("similarity") or 0) >= 92):
                    score += 3; finding["risk_contribution"]=3; finding["explanation"]="A verified brand favicon matched an unverified domain; this is a corroborating impersonation signal, not confirmation of fraud."; contributions.append({"source":"favicon_similarity","points":3,"explanation":finding["explanation"]})
    certificate_influence=None
    if certificate:
        certificate_assessment=certificate.get("risk",certificate) if isinstance(certificate,dict) else {}
        cert_score=int(certificate_assessment.get("score",0) or 0)
        # Certificate evidence has a bounded 25-point influence. This is a
        # calibrated influence, not a raw addition of two unrelated scales.
        added=min(25, round(cert_score * 0.25))
        if added:
            score += added
            contributions.append({"source":"certificate_risk","points":added,"explanation":f"Certificate risk score {cert_score}/100 contributes a bounded {added} points to overall reputation; certificate findings remain separately visible."})
        certificate_influence={"certificate_score":cert_score,"added_points":added,"method":"bounded_weighted_influence_25_percent_max","explanation":"The certificate score is normalized before contributing to overall risk to avoid double-counting provider and certificate evidence."}
    level = "Critical" if score >= 80 else "High" if score >= 55 else "Medium" if score >= 25 else "Low"
    confidence = "High" if len(phishing["evidence"]) >= 2 else "Medium" if phishing["evidence"] else "Low"
    return {"score": min(score, 100), "level": level, "confidence": confidence, "summary": "Risk is based on explainable local signals and available passive checks.", "method": "Rule-based MVP; ML classifier hook is ready for labelled training data.", "contributions": contributions, "certificate_influence":certificate_influence}
