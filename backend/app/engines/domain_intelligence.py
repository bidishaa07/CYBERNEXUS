import hashlib, ipaddress, json, re, socket
from difflib import SequenceMatcher
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
import httpx
from backend.app.core.config import settings
from backend.app.engines.rdap import fetch_rdap as fetch_rdap_engine
from backend.app.engines.ipinfo import collect_ip_intelligence
from backend.app.engines.safe_http import fetch as safe_fetch
from backend.app.engines.logo_similarity import fingerprint, detect_format
from backend.app.engines.image_intelligence import discover

BRAND_DOMAINS={"paypal":"paypal.com","google":"google.com","microsoft":"microsoft.com","apple":"apple.com","amazon":"amazon.com","facebook":"facebook.com","instagram":"instagram.com","netflix":"netflix.com","github":"github.com","linkedin":"linkedin.com","bank":""}
COMMON_SUFFIXES={"co.uk","com.au","co.in","co.jp","com.br","co.nz"}
CONFUSABLES={"0":"o","1":"l","3":"e","5":"s","7":"t","@":"a","$":"s","а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y"}

def registered_domain(domain):
    labels=domain.lower().strip('.').split('.')
    suffix='.'.join(labels[-2:]) if len(labels)>=2 else domain
    if suffix in COMMON_SUFFIXES and len(labels)>=3: return '.'.join(labels[-3:])
    return suffix

def _levenshtein(a,b):
    prev=list(range(len(b)+1))
    for i,x in enumerate(a,1):
        cur=[i]
        for j,y in enumerate(b,1): cur.append(min(cur[-1]+1,prev[j]+1,prev[j-1]+(x!=y)))
        prev=cur
    return prev[-1]

def _damerau(a,b):
    d={(i,0):i for i in range(len(a)+1)}|{(0,j):j for j in range(len(b)+1)}
    for i in range(1,len(a)+1):
        for j in range(1,len(b)+1):
            d[i,j]=min(d[i-1,j]+1,d[i,j-1]+1,d[i-1,j-1]+(a[i-1]!=b[j-1]))
            if i>1 and j>1 and a[i-1]==b[j-2] and a[i-2]==b[j-1]: d[i,j]=min(d[i,j],d[i-2,j-2]+1)
    return d[len(a),len(b)]

def _confusable_form(value):
    return ''.join(CONFUSABLES.get(char, char) for char in value.casefold())

def _manipulation(suspect, target):
    if suspect == target: return "exact brand label"
    if _confusable_form(suspect) == target and suspect != target: return "homoglyph or lookalike substitution"
    if len(suspect) == len(target):
        mismatches=sum(a != b for a,b in zip(suspect,target))
        if mismatches == 1: return "character substitution"
        for i in range(len(suspect)-1):
            if suspect[:i]+suspect[i+1]+suspect[i]+suspect[i+2:] == target: return "character transposition"
    if len(suspect) == len(target)+1:
        return "character insertion"
    if len(suspect)+1 == len(target):
        return "character deletion"
    return "edit-distance similarity"

def analyze_domain(domain):
    rd=registered_domain(domain); ascii_domain=domain.encode('idna').decode('ascii').lower(); suspicious=[]
    if ascii_domain.startswith('xn--') or '.xn--' in ascii_domain: suspicious.append({"type":"homograph","severity":"high","message":"Punycode/IDN label detected"})
    comparisons=[]
    suspect_label=rd.rsplit('.',1)[0]
    for brand,official in BRAND_DOMAINS.items():
        if not official: continue
        target=official.split('.')[0]
        distance=_damerau(suspect_label,target); levenshtein=_levenshtein(suspect_label,target)
        similarity=round(SequenceMatcher(None,_confusable_form(suspect_label),target).ratio()*100,2)
        same_label=suspect_label == target
        tld_variation=rd != official and same_label
        if not same_label and (distance <= max(2, len(target)//3) or similarity >= 68):
            comparisons.append({"brand":brand,"official_domain":official,"suspected_domain":rd,"edit_distance":distance,"levenshtein_distance":levenshtein,"similarity_percent":similarity,"manipulation":_manipulation(suspect_label,target),"risk":"high" if similarity>=75 else "medium"})
        elif tld_variation:
            comparisons.append({"brand":brand,"official_domain":official,"suspected_domain":rd,"edit_distance":0,"levenshtein_distance":0,"similarity_percent":100,"manipulation":"TLD variation","risk":"medium"})
    for label in domain.split('.')[:-2]:
        if any(word in label.lower() for word in BRAND_DOMAINS): suspicious.append({"type":"impersonating_subdomain","severity":"high","message":f"Brand-like subdomain label: {label}"})
    return {"domain":domain,"registered_domain":rd,"idna_domain":ascii_domain,"brand_matches":comparisons,"indicators":suspicious,"ownership":{"status":"unknown","confidence":"none","message":"Ownership is not inferred from branding alone."}}

def fetch_rdap(domain):
    return fetch_rdap_engine(domain)

def resolve_infrastructure(domain):
    return collect_ip_intelligence(domain)

def analyze_identity(url):
    try:
        with httpx.stream("GET",url,headers={"User-Agent":"DigitalTrustIntelligence/1.0"},follow_redirects=False,timeout=6) as response:
            content_type=response.headers.get("content-type","").lower()
            if "text/html" not in content_type: return {"status":"skipped","reason":"Response is not HTML","content_type":content_type}
            chunks=[]; total=0
            for chunk in response.iter_bytes():
                remaining=1000000-total
                if remaining<=0: break
                chunks.append(chunk[:remaining]); total+=len(chunks[-1])
            body=b"".join(chunks); text=body.decode(response.encoding or 'utf-8','ignore'); title=(re.search(r'<title[^>]*>(.*?)</title>',text,re.I|re.S) or [None,''])[1].strip()[:300]; meta=(re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)',text,re.I) or [None,''])[1].strip()[:500]
            discovered=discover(url,text)
            for manifest_url in discovered["manifests"][:1]:
                try:
                    manifest=safe_fetch(manifest_url,max_bytes=100000).body.decode("utf-8","replace"); data=json.loads(manifest)
                    for icon in data.get("icons",[]) if isinstance(data,dict) else []:
                        if icon.get("src"): discovered["favicons"].append({"url":urljoin(manifest_url,icon["src"]),"source":"web-app-manifest","sizes":icon.get("sizes")})
                except Exception: pass
            def fetch_assets(items, limit):
                results=[]
                for candidate in items[:limit]:
                    try:
                        asset=safe_fetch(candidate["url"], max_bytes=2*1024*1024); content_type=asset.headers.get("content-type","").split(";",1)[0].lower()
                        if not (content_type.startswith("image/") or content_type in {"image/svg+xml","application/svg+xml"}): results.append({**candidate,"status":"rejected","reason":"unsupported_content_type","content_type":content_type}); continue
                        info=fingerprint(asset.body); detected=detect_format(asset.body)
                        mime_formats={"image/png":"PNG","image/jpeg":"JPEG","image/webp":"WEBP","image/x-icon":"ICO","image/vnd.microsoft.icon":"ICO","image/svg+xml":"SVG","application/svg+xml":"SVG"}
                        if info.get("status") != "available": results.append({**candidate,**info,"content_type":content_type}); continue
                        if content_type in mime_formats and detected != mime_formats[content_type]: results.append({**candidate,"status":"rejected","reason":"mime_signature_mismatch","content_type":content_type,"detected_format":detected}); continue
                        results.append({**candidate,**info,"content_type":content_type,"detected_format":detected,"retrieved_at":datetime.now(timezone.utc).isoformat()})
                    except Exception as exc: results.append({**candidate,"status":"unavailable","reason":type(exc).__name__})
                return results
            favicon_assets=fetch_assets(discovered["favicons"],8); logo_assets=fetch_assets(discovered["logos"],8)
            available_favicons=[item for item in favicon_assets if item.get("status")=="available"]
            available_logos=[item for item in logo_assets if item.get("status")=="available"]
            return {"status":"available","http_status":response.status_code,"title":re.sub(r'\s+',' ',title),"meta_description":re.sub(r'\s+',' ',meta),"content_sha256":hashlib.sha256(body).hexdigest(),"favicon_url":available_favicons[0].get("url") if available_favicons else urljoin(url,'/favicon.ico'),"favicon_candidates":favicon_assets,"favicon_status":"available" if available_favicons else "FAVICON_NOT_FOUND","logo_candidates":[item["url"] for item in discovered["logos"]],"logo_assets":logo_assets,"logo_status":"available" if available_logos else "LOGO_NOT_FOUND","logo_comparison":{"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No verified reference logo is configured"},"favicon_comparison":{"status":"COMPARISON_UNAVAILABLE_NO_VERIFIED_REFERENCE","reason":"No verified reference favicon is configured"},"identity_assessment":"UNKNOWN","login_indicators":bool(re.search(r'login|sign[ -]?in|password|credential',text,re.I)),"payment_indicators":bool(re.search(r'payment|card|wallet|bank',text,re.I)),"scripts":re.findall(r'<script[^>]+src=["\']([^"\']+)',text,re.I)[:50],"truncated":total>=1000000}
    except Exception as exc: return {"status":"unavailable","reason":type(exc).__name__}

def collect(url,domain):
    return {"domain":analyze_domain(domain),"rdap":fetch_rdap(domain),"infrastructure":resolve_infrastructure(domain),"identity":analyze_identity(url)}
