import re
def correlate(scans, reports):
    domains={}
    for item in scans: domains.setdefault(item.domain, []).append({"type":"scan","id":item.id,"url":item.url})
    for item in reports:
        host=re.sub(r"^https?://", "", item.url).split('/')[0].lower()
        domains.setdefault(host, []).append({"type":"community_report","id":item.id,"url":item.url})
    clusters=[{"key":key,"indicators":value,"reason":"Repeated domain across submitted intelligence"} for key,value in domains.items() if len(value)>1]
    return {"clusters":clusters,"count":len(clusters),"method":"Deterministic exact-domain matching; no relationship is asserted without shared evidence."}
