"""Deterministic HTML metadata discovery for favicon and logo candidates."""
from __future__ import annotations
import json, re
from urllib.parse import urljoin

def _attrs(tag: str) -> dict[str,str]:
    return {key.lower(): value for key, value in re.findall(r'''([:\w-]+)\s*=\s*["']([^"']*)["']''', tag, re.I)}

def discover(base_url: str, html: str) -> dict:
    favicons=[]; logos=[]; manifests=[]
    for tag in re.findall(r"<link\b[^>]*>",html,re.I):
        attrs=_attrs(tag); rel=attrs.get("rel","").lower(); href=attrs.get("href")
        if not href: continue
        absolute=urljoin(base_url,href)
        if any(token in rel for token in ("icon","shortcut icon","apple-touch-icon","mask-icon")):
            favicons.append({"url":absolute,"source":"link","rel":rel,"sizes":attrs.get("sizes")})
        if "manifest" in rel: manifests.append(absolute)
    for tag in re.findall(r"<(?:img|source)\b[^>]*>",html,re.I):
        attrs=_attrs(tag); source=attrs.get("src") or attrs.get("data-src")
        if source:
            absolute=urljoin(base_url,source)
            label=" ".join([attrs.get("alt",""),attrs.get("title",""),source])
            if re.search(r"logo|brand|wordmark|masthead",label,re.I): logos.append({"url":absolute,"source":"html-image","label":label})
    for pattern, source in ((r'''<meta\b[^>]*(?:property|name)\s*=\s*["'](?:og:image|twitter:image)["'][^>]*>''',"metadata"),(r'''<meta\b[^>]*content\s*=\s*["'][^"']+["'][^>]*(?:property|name)\s*=\s*["'](?:og:image|twitter:image)["'][^>]*>''',"metadata")):
        for tag in re.findall(pattern,html,re.I):
            attrs=_attrs(tag); content=attrs.get("content")
            if content: logos.append({"url":urljoin(base_url,content),"source":source})
    for tag in re.findall(r'''<script\b[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>''',html,re.I|re.S):
        try:
            data=json.loads(tag); items=data if isinstance(data,list) else [data]
            for item in items:
                if isinstance(item,dict) and item.get("logo"):
                    logo=item["logo"] if isinstance(item["logo"],str) else item["logo"].get("url")
                    if logo: logos.append({"url":urljoin(base_url,logo),"source":"organization-schema"})
        except (ValueError,TypeError): pass
    favicons.append({"url":urljoin(base_url,"/favicon.ico"),"source":"standard-fallback"})
    def unique(items):
        seen=set(); result=[]
        for item in items:
            if item["url"] not in seen: seen.add(item["url"]); result.append(item)
        return result
    return {"favicons":unique(favicons)[:15],"logos":unique(logos)[:15],"manifests":list(dict.fromkeys(manifests))[:3]}
