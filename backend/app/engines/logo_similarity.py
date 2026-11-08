"""Bounded, non-executing image fingerprints for verified brand comparisons."""
from __future__ import annotations
from io import BytesIO
import hashlib
from PIL import Image, UnidentifiedImageError

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_DIMENSION = 2400
MAX_PIXELS = 2400 * 2400

def detect_format(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"): return "PNG"
    if data[:3] == b"\xff\xd8\xff": return "JPEG"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP": return "WEBP"
    if data[:4] == b"\x00\x00\x01\x00": return "ICO"
    if data.lstrip().startswith(b"<svg") or b"<svg" in data[:512].lower(): return "SVG"
    return None

def _ico_entries(data: bytes) -> int:
    if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00": return 0
    count=int.from_bytes(data[4:6],"little")
    if count > 64 or len(data) < 6 + count*16: return 0
    valid=0
    for offset in range(6,6+count*16,16):
        size=int.from_bytes(data[offset+8:offset+12],"little"); start=int.from_bytes(data[offset+12:offset+16],"little")
        if size and start + size <= len(data): valid += 1
    return valid

def fingerprint(image_bytes: bytes) -> dict:
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return {"status":"rejected", "reason":"image_too_large"}
    detected=detect_format(image_bytes)
    if not detected:
        return {"status":"rejected", "reason":"unsupported_or_invalid_signature"}
    if detected == "SVG":
        if b"<script" in image_bytes.lower() or b"<!entity" in image_bytes.lower(): return {"status":"rejected", "reason":"unsafe_svg"}
        # SVG is treated as inert text; dimensions are optional and the hash is
        # over a bounded canonical byte representation, never rendered.
        digest=hashlib.sha256(image_bytes).hexdigest()
        return {"status":"available","sha256":digest,"phash":digest,"dhash":digest,"ahash":digest,"width":None,"height":None,"format":"SVG","ico_entries":0}
    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image.verify()
        with Image.open(BytesIO(image_bytes)) as image:
            if image.width > MAX_DIMENSION or image.height > MAX_DIMENSION or image.width * image.height > MAX_PIXELS:
                return {"status":"rejected", "reason":"image_dimensions_too_large"}
            rgb=image.convert("RGBA").resize((32,32))
            background=Image.new("RGBA",rgb.size,(255,255,255,255)); background.alpha_composite(rgb)
            gray=list(background.convert("L").getdata()); average=sum(gray)/len(gray)
            phash="".join("1" if pixel >= average else "0" for pixel in gray)
            small=background.convert("L").resize((9,8)); values=list(small.getdata())
            dhash="".join("1" if values[row*9+col] >= values[row*9+col+1] else "0" for row in range(8) for col in range(8))
            ahash="".join("1" if pixel >= average else "0" for pixel in gray)
            return {"status":"available", "sha256":hashlib.sha256(image_bytes).hexdigest(), "phash":phash, "dhash":dhash, "ahash":ahash, "width":image.width, "height":image.height, "format":detected, "ico_entries":_ico_entries(image_bytes) if detected == "ICO" else 0}
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError):
        return {"status":"rejected", "reason":"invalid_image"}

def compare(candidate_hash: str, reference_hash: str) -> dict:
    if not candidate_hash or not reference_hash or len(candidate_hash) != len(reference_hash):
        return {"status":"unavailable", "reason":"missing_or_incompatible_fingerprint"}
    distance=sum(a != b for a,b in zip(candidate_hash, reference_hash))
    score=round((1 - distance/len(candidate_hash))*100, 2)
    return {"status":"compared", "similarity_percent":score, "hamming_distance":distance, "method":"32x32 average-hash + Hamming distance", "confidence":"high" if score >= 92 else "medium" if score >= 78 else "low"}

def compare_fingerprints(candidate: dict, reference: dict) -> dict:
    if not candidate or not reference or candidate.get("status") != "available" or reference.get("status") != "available":
        return {"status":"unavailable","reason":"missing_image_fingerprint"}
    exact=bool(candidate.get("sha256") and candidate.get("sha256") == reference.get("sha256"))
    phash=compare(candidate.get("phash"),reference.get("phash")); dhash=compare(candidate.get("dhash"),reference.get("dhash"))
    if phash.get("status") != "compared" or dhash.get("status") != "compared": return {"status":"unavailable","reason":"incompatible_image_fingerprint"}
    score=round(phash["similarity_percent"]*.6 + dhash["similarity_percent"]*.4,2)
    return {"status":"compared","exact_match":exact,"similarity_percent":score,"perceptual_similarity":phash["similarity_percent"],"difference_similarity":dhash["similarity_percent"],"method":"SHA-256 exact match + average-hash + difference-hash","confidence":"high" if exact or score >= 92 else "medium" if score >= 78 else "low","limitations":"Visual similarity is supporting evidence, not proof of ownership or fraud."}
