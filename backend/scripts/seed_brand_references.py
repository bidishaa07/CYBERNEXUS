"""Import references from a reviewed, official-source manifest.

The command never invents bytes or marks arbitrary URLs as trusted.  Use
--approve only when the operator has reviewed the manifest and source policy.
"""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone
from backend.app.db.session import SessionLocal
from backend.app.models.models import BrandRegistry, BrandImageReference, BrandVerificationAudit
from backend.app.engines.safe_http import fetch as safe_fetch
from backend.app.engines.logo_similarity import fingerprint, MAX_IMAGE_BYTES

MANIFEST = [
    {"brand_name":"Google","official_domain":"google.com","asset_type":"favicon","url":"https://www.google.com/favicon.ico"},
    {"brand_name":"Microsoft","official_domain":"microsoft.com","asset_type":"favicon","url":"https://www.microsoft.com/favicon.ico"},
    {"brand_name":"Apple","official_domain":"apple.com","asset_type":"favicon","url":"https://www.apple.com/favicon.ico"},
    {"brand_name":"Amazon","official_domain":"amazon.com","asset_type":"favicon","url":"https://www.amazon.com/favicon.ico"},
    {"brand_name":"GitHub","official_domain":"github.com","asset_type":"favicon","url":"https://github.com/favicon.ico"},
    {"brand_name":"Google","official_domain":"google.com","asset_type":"logo","url":"https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"},
    {"brand_name":"GitHub","official_domain":"github.com","asset_type":"logo","url":"https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"},
]

def main(approve: bool = False):
    db=SessionLocal(); report={"brands_imported":0,"logos_imported":0,"favicons_imported":0,"approved":0,"pending":0,"failed":[]}
    try:
        for item in MANIFEST:
            try:
                brand=db.query(BrandRegistry).filter(BrandRegistry.official_domain==item["official_domain"]).first()
                if not brand:
                    brand=BrandRegistry(brand_name=item["brand_name"],official_domain=item["official_domain"],official_website="https://"+item["official_domain"],verification_status="unknown",source="reviewed official-source manifest",source_reliability="high"); db.add(brand); db.flush(); report["brands_imported"]+=1
                response=safe_fetch(item["url"],max_bytes=MAX_IMAGE_BYTES)
                content_type=response.headers.get("content-type","").split(";",1)[0].lower(); info=fingerprint(response.body)
                if response.status_code != 200 or info.get("status") != "available": raise ValueError(info.get("reason",f"http_{response.status_code}"))
                duplicate=db.query(BrandImageReference).filter(BrandImageReference.brand_id==brand.id,BrandImageReference.asset_type==item["asset_type"],BrandImageReference.sha256==info["sha256"]).first()
                if duplicate: continue
                approval="approved" if approve else "pending"; now=datetime.now(timezone.utc)
                row=BrandImageReference(brand_id=brand.id,asset_type=item["asset_type"],original_source=item["url"],content_type=content_type,width=info.get("width"),height=info.get("height"),sha256=info["sha256"],phash=info["phash"],dhash=info.get("dhash"),ahash=info.get("ahash"),image_bytes=response.body,approval_status=approval,source=item["url"],uploaded_at=now,approved_at=now if approve else None)
                db.add(row); db.flush(); db.add(BrandVerificationAudit(brand_id=brand.id,actor="seed-review",action="official_reference_approved" if approve else "official_reference_imported",details_json=json.dumps({"asset_id":row.id,"asset_type":item["asset_type"],"source":item["url"]})))
                report["approved" if approve else "pending"]+=1; report["logos_imported" if item["asset_type"]=="logo" else "favicons_imported"]+=1
            except Exception as exc:
                report["failed"].append({"source":item["url"],"error":type(exc).__name__})
        db.commit(); return report
    finally: db.close()

if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--approve",action="store_true",help="Approve only this reviewed official-source manifest")
    print(json.dumps(main(parser.parse_args().approve),indent=2))
