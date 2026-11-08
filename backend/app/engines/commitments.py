import hashlib, json
def commitment(payload: dict):
    canonical=json.dumps(payload, sort_keys=True, separators=(",",":"), default=str).encode()
    return {"algorithm":"sha256","fingerprint":hashlib.sha256(canonical).hexdigest(),"canonical_payload":canonical.decode()}
