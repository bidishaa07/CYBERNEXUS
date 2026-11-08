from unittest.mock import patch
import httpx
from backend.app.engines.rdap import fetch_rdap

def response(status, headers=None, json_data=None, url="https://rdap.org/domain/example.com"):
    request=httpx.Request("GET",url)
    return httpx.Response(status,headers=headers or {"content-type":"application/rdap+json"},json=json_data,request=request)

class FakeClient:
    responses=[]
    def __init__(self,*args,**kwargs): pass
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def get(self,*args,**kwargs): return self.responses.pop(0)

@patch("backend.app.engines.rdap._host_ips", return_value=["203.0.113.10"])
def test_rdap_follows_valid_302(mock_dns):
    FakeClient.responses=[response(302,{"location":"https://rdap.verisign.com/com/v1/domain/example.com"}),response(200,{"content-type":"application/rdap+json"},{"ldhName":"example.com","events":[],"nameservers":[]})]
    with patch("backend.app.engines.rdap.httpx.Client",FakeClient):
        result=fetch_rdap("example.com",bootstrap_hosts={"rdap.org","rdap.verisign.com"})
    assert result["status"]=="available"; assert result["domain"]=="example.com"; assert len(result["redirects"])==1

@patch("backend.app.engines.rdap._host_ips", return_value=["203.0.113.10"])
def test_rdap_blocks_untrusted_redirect(mock_dns):
    FakeClient.responses=[response(302,{"location":"https://localhost/internal"})]
    with patch("backend.app.engines.rdap.httpx.Client",FakeClient): result=fetch_rdap("example.com",bootstrap_hosts={"rdap.org"})
    assert result["status"]=="blocked"

@patch("backend.app.engines.rdap._host_ips", return_value=["203.0.113.10"])
def test_rdap_rejects_malformed_json(mock_dns):
    FakeClient.responses=[httpx.Response(200,headers={"content-type":"application/rdap+json"},content=b"bad",request=httpx.Request("GET","https://rdap.org/domain/example.com"))]
    with patch("backend.app.engines.rdap.httpx.Client",FakeClient): result=fetch_rdap("example.com",bootstrap_hosts={"rdap.org"})
    assert result["status"]=="failed"
