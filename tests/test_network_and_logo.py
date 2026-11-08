from backend.app.engines.logo_similarity import fingerprint, compare, compare_fingerprints
from backend.app.engines.image_intelligence import discover
from backend.app.engines.network_intelligence import classify_hosting, enrich_record

def test_logo_fingerprint_and_comparison_are_real_and_explainable():
    from PIL import Image
    from io import BytesIO
    stream=BytesIO(); Image.new("RGB",(32,32),(10,20,30)).save(stream,format="PNG")
    info=fingerprint(stream.getvalue())
    assert info["status"] == "available"
    result=compare(info["phash"],info["phash"])
    assert result["similarity_percent"] == 100
    assert result["method"]

def test_invalid_and_oversized_logo_are_rejected():
    assert fingerprint(b"not an image")["status"] == "rejected"
    assert fingerprint(b"x" * (2 * 1024 * 1024 + 1))["reason"] == "image_too_large"

def test_network_fallback_fills_prefix_without_inventing_hosting():
    primary={"source":"IPinfo","ip":"8.8.8.8","status":"queried","asn_number":None,"network_range":None}
    fallback={"source":"RIPE Stat","ip":"8.8.8.8","status":"queried","announced_prefix":"8.8.8.0/24","asns":[15169]}
    result=enrich_record(primary,fallback)
    assert result["network_range"] == "8.8.8.0/24"
    assert result["asn_number"] == "AS15169"
    assert result["hosting_classification"]["classification"] == "Unknown"

def test_explicit_hosting_classification_keeps_provenance():
    result=classify_hosting([{"source":"IPinfo","classification":"CDN"}])
    assert result["classification"] == "CDN"
    assert result["confidence"] == "medium"

def test_favicon_and_logo_discovery_supports_metadata_manifest_and_schema():
    html='''<head><link rel="icon" href="/icon.png" sizes="32x32"><link rel="apple-touch-icon" href="icons/apple.png"><link rel="manifest" href="/manifest.json"><meta property="og:image" content="/brand-card.png"><script type="application/ld+json">{"@type":"Organization","logo":"/official.svg"}</script></head><img src="/brand-logo.png" alt="Company logo">'''
    result=discover("https://example.com/page",html)
    assert any(item["url"] == "https://example.com/icon.png" for item in result["favicons"])
    assert any(item["url"] == "https://example.com/brand-logo.png" for item in result["logos"])
    assert any(item["url"] == "https://example.com/official.svg" for item in result["logos"])

def test_fingerprint_contains_exact_perceptual_and_difference_hashes():
    from PIL import Image
    from io import BytesIO
    stream=BytesIO(); Image.new("RGBA",(16,16),(255,0,0,128)).save(stream,format="PNG")
    result=fingerprint(stream.getvalue())
    assert result["sha256"] and result["phash"] and result["dhash"] and result["ahash"]
    compared=compare_fingerprints(result,result)
    assert compared["exact_match"] is True
    assert compared["similarity_percent"] == 100

def test_svg_is_inert_and_scripted_svg_is_rejected():
    assert fingerprint(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>')["format"] == "SVG"
    assert fingerprint(b'<svg><script>alert(1)</script></svg>')["reason"] == "unsafe_svg"

def test_supported_binary_favicon_formats_are_signature_validated():
    from PIL import Image
    from io import BytesIO
    for image_format, expected in (("PNG","PNG"),("JPEG","JPEG"),("WEBP","WEBP"),("ICO","ICO")):
        stream=BytesIO(); Image.new("RGB",(16,16),(30,60,90)).save(stream,format=image_format)
        result=fingerprint(stream.getvalue())
        assert result["status"] == "available"
        assert result["format"] == expected
    assert fingerprint(b"not-an-ico")["status"] == "rejected"
