from backend.app.engines.certificate_transparency import analyze, detect_anomalies

class Response:
    def __init__(self,payload,status=200,content_type="application/json"):
        self.status_code=status; self.headers={"content-type":content_type}; self._payload=payload
    def json(self): return self._payload

class Client:
    def __init__(self,response): self.response=response
    def get(self,*args,**kwargs): return self.response

def entry(cert_id, issuer, names, fingerprint, date):
    return {"id":cert_id,"issuer_name":issuer,"common_name":names[0],"name_value":"\n".join(names),"sha256":fingerprint,"serial_number":cert_id,"not_before":date,"not_after":"2027-01-01T00:00:00Z","entry_timestamp":date}

def test_normal_history_is_normalized_and_duplicate_is_reported():
    payload=[entry(1,"CA One",["example.com"],"a"*64,"2025-01-01T00:00:00Z"),entry(1,"CA One",["example.com"],"a"*64,"2025-01-01T00:00:00Z")]
    result=analyze("example.com",Client(Response(payload)))
    assert result["status"]=="AVAILABLE" and result["record_count"]==2
    assert any(item["finding_type"]=="duplicate_certificate_observation" for item in result["anomalies"])

def test_issuer_change_and_san_addition_are_evidence_backed():
    records=[_ for _ in [
        {"issuer":"CA One","san_domains":["example.com"],"fingerprint_sha256":"1","not_before":"2025-01-01","observation_timestamp":"2025-01-01"},
        {"issuer":"CA Two","san_domains":["example.com","login.example.com"],"fingerprint_sha256":"2","not_before":"2025-02-01","observation_timestamp":"2025-02-01"},
    ]]
    findings=detect_anomalies("example.com",records)
    types={item["finding_type"] for item in findings}
    assert {"issuer_change","san_addition"}.issubset(types)
    assert all(item["source"]=="crt.sh" for item in findings)

def test_malformed_and_unavailable_ct_are_not_clean():
    malformed=analyze("example.com",Client(Response({"not":"an array"})))
    assert malformed["status"]=="UNAVAILABLE" and malformed["records"]==[]
    unavailable=analyze("example.com",Client(Response([],503)))
    assert unavailable["status"]=="UNAVAILABLE"
