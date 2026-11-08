"""Private off-chain evidence storage, manifests and integrity verification."""
import hashlib
import json
import os
import re
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.exc import IntegrityError

from backend.app.core.config import settings
from backend.app.models.models import (
    EvidenceManifest,
    EvidenceObject,
    EvidenceReference,
    ProvenanceEvent,
    ReportRevision,
    ThreatIntelligenceReport,
)
from backend.app.services.ledger import record_event

MANIFEST_DOMAIN = "CYBERNEXUS:EVIDENCE_MANIFEST:v1"
HASH_ALGORITHM = "SHA-256"
ACCESS_CLASSES = {"PRIVATE", "REPORT_OWNER", "AUTHORIZED_USERS"}
MAX_FILENAME_LENGTH = 120


def _now():
    return datetime.now(timezone.utc)


def _root():
    root = Path(settings.evidence_storage_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _max_bytes():
    return max(1, int(settings.evidence_max_bytes))


def _fernet():
    """Return the at-rest encryption key; production requires explicit keying."""
    configured = (settings.evidence_encryption_key or "").strip()
    if configured:
        try:
            return Fernet(configured.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("EVIDENCE_ENCRYPTION_KEY must be a valid Fernet key") from exc
    if settings.environment.lower() == "production":
        raise ValueError("encrypted evidence storage requires EVIDENCE_ENCRYPTION_KEY in production")
    root = _root()
    key_file = root / ".evidence.key"
    if key_file.exists():
        return Fernet(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return Fernet(key)


def _malware_scan(data):
    """Scan through configured HTTP or ClamAV; never treats no scanner as clean."""
    if settings.evidence_malware_scan_url:
        try:
            response = httpx.post(
                settings.evidence_malware_scan_url,
                content=data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=settings.evidence_malware_scan_timeout_seconds,
            )
            response.raise_for_status()
            body = response.json() if response.content else {}
            status = str(body.get("status") or body.get("verdict") or "UNKNOWN").upper()
            if status in {"CLEAN", "MALICIOUS", "INFECTED", "UNKNOWN"}:
                return {"status": "MALICIOUS" if status == "INFECTED" else status, "provider": "configured-http-scanner"}
            return {"status": "UNKNOWN", "provider": "configured-http-scanner", "error": "unrecognized scanner response"}
        except Exception as exc:
            return {"status": "UNAVAILABLE", "provider": "configured-http-scanner", "error": type(exc).__name__}
    if settings.evidence_clamav_host:
        try:
            with socket.create_connection((settings.evidence_clamav_host, int(settings.evidence_clamav_port)), timeout=5) as sock:
                sock.sendall(b"zINSTREAM\0")
                for start in range(0, len(data), 1024 * 1024):
                    chunk = data[start:start + 1024 * 1024]
                    sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
                sock.sendall((0).to_bytes(4, "big"))
                result = sock.recv(4096).decode("utf-8", "replace").upper()
            return {"status": "MALICIOUS" if "FOUND" in result else "CLEAN" if "OK" in result else "UNKNOWN", "provider": "clamav"}
        except Exception as exc:
            return {"status": "UNAVAILABLE", "provider": "clamav", "error": type(exc).__name__}
    return {"status": "UNKNOWN", "provider": "not_configured", "error": "no malware scanner configured"}


def _stored_bytes(obj):
    if not obj.storage_uri:
        raise FileNotFoundError(obj.id)
    path = _safe_relative(obj.storage_uri)
    if not path.exists():
        raise FileNotFoundError(obj.id)
    raw = path.read_bytes()
    if str(obj.encryption_status).startswith("FERNET"):
        return _fernet().decrypt(raw)
    return raw


def _safe_name(name):
    base = Path(str(name or "evidence")).name
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip(".")[:MAX_FILENAME_LENGTH]
    return base or "evidence"


def _safe_relative(path):
    root = _root()
    candidate = (root / path).resolve()
    if os.path.commonpath([str(root), str(candidate)]) != str(root):
        raise ValueError("evidence storage path is outside the configured storage root")
    return candidate


def _hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _validate_content(content_type, data):
    content_type = (content_type or "application/octet-stream").split(";", 1)[0].lower()
    if not data:
        raise ValueError("evidence file is empty")
    signatures = {
        "application/pdf": data.startswith(b"%PDF-"),
        "image/png": data.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": data.startswith(b"\xff\xd8\xff"),
        "image/gif": data.startswith((b"GIF87a", b"GIF89a")),
        "application/zip": data.startswith(b"PK\x03\x04"),
    }
    if content_type in signatures and not signatures[content_type]:
        raise ValueError("content does not match its declared file type")
    if content_type in {"application/json", "text/json"}:
        try:
            json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid JSON evidence") from exc
    return content_type


def _event(db, event_type, actor, report, revision, evidence_id, details):
    detail_hash = hashlib.sha256(
        json.dumps(details or {}, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    ledger = record_event(
        db,
        event_type,
        actor,
        report_id=report.id,
        revision_id=revision.id,
        details=details,
        evidence_refs=[str(evidence_id)],
        dedupe_key=f"{event_type}:evidence:{evidence_id}:{detail_hash}",
    )
    db.add(ProvenanceEvent(
        report_id=report.id,
        revision_id=revision.id,
        actor_user_id=actor,
        event_type=event_type,
        source_type="EVIDENCE_OBJECT",
        source_id=str(evidence_id),
        ledger_event_id=ledger.id,
        details_json=json.dumps(details, sort_keys=True),
        created_at=_now(),
    ))
    return ledger


def _manifest_payload(db, report_id, revision_id):
    rows = (
        db.query(EvidenceReference, EvidenceObject)
        .join(EvidenceObject, EvidenceObject.id == EvidenceReference.evidence_object_id)
        .filter(EvidenceReference.revision_id == revision_id)
        .order_by(EvidenceObject.id.asc(), EvidenceReference.reference_type.asc())
        .all()
    )
    entries = []
    for ref, obj in rows:
        entries.append({
            "evidence_id": obj.id,
            "content_hash": obj.object_hash,
            "hash_algorithm": obj.hash_algorithm,
            "content_type": obj.content_type,
            "size_bytes": obj.size_bytes,
            "reference_type": ref.reference_type,
            "description": ref.description or "",
        })
    return {
        "schema": "threat-evidence-manifest-v1",
        "report_id": report_id,
        "revision_id": revision_id,
        "entries": entries,
    }


def _canonical_manifest(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def create_manifest(db, report, revision, actor):
    payload = _manifest_payload(db, report.id, revision.id)
    canonical = _canonical_manifest(payload)
    digest = hashlib.sha256((MANIFEST_DOMAIN + ":" + canonical).encode("utf-8")).hexdigest()
    latest = db.query(EvidenceManifest).filter_by(revision_id=revision.id).order_by(EvidenceManifest.version.desc()).first()
    version = (latest.version + 1) if latest else 1
    row = EvidenceManifest(
        report_id=report.id,
        revision_id=revision.id,
        version=version,
        canonical_manifest=canonical,
        manifest_hash=digest,
        hash_algorithm=HASH_ALGORITHM,
        created_by=actor,
        created_at=_now(),
    )
    db.add(row)
    db.flush()
    return row


def upload(db, report, revision, actor, data, filename, content_type, reference_type="SUPPORTING", description="", access_classification="PRIVATE", metadata=None):
    if access_classification not in ACCESS_CLASSES:
        raise ValueError("invalid evidence access classification")
    if len(data) > _max_bytes():
        raise ValueError(f"evidence exceeds the {_max_bytes()} byte limit")
    content_type = _validate_content(content_type, data)
    malware = _malware_scan(data)
    if malware["status"] == "MALICIOUS":
        raise ValueError("evidence rejected by malware scanner")
    digest = _hash_bytes(data)
    obj = db.query(EvidenceObject).filter_by(owner_user_id=actor, object_hash=digest).first()
    if not obj:
        relative = Path("objects") / digest[:2] / f"{uuid.uuid4().hex}-{_safe_name(filename)}"
        target = _safe_relative(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        encrypted = _fernet().encrypt(data)
        target.write_bytes(encrypted)
        obj = EvidenceObject(
            owner_user_id=actor,
            report_id=report.id,
            revision_id=revision.id,
            object_hash=digest,
            hash_algorithm=HASH_ALGORITHM,
            storage_uri=relative.as_posix(),
            content_type=content_type,
            size_bytes=len(data),
            access_classification=access_classification,
            encryption_status="FERNET_AES128_HMAC",
            malware_scan_status=malware["status"],
            malware_scan_provider=malware.get("provider"),
            malware_scanned_at=_now(),
            retention_expires_at=_now() + timedelta(days=max(1, int(settings.evidence_default_retention_days))),
            metadata_json=json.dumps({"filename": _safe_name(filename), **(metadata or {})}, sort_keys=True),
            created_at=_now(),
        )
        db.add(obj)
        db.flush()
    ref = EvidenceReference(
        revision_id=revision.id,
        evidence_object_id=obj.id,
        reference_type=str(reference_type or "SUPPORTING")[:80],
        description=str(description or "")[:4000],
        created_at=_now(),
    )
    db.add(ref)
    db.flush()
    manifest = create_manifest(db, report, revision, actor)
    ledger = _event(db, "EVIDENCE_ADDED", actor, report, revision, obj.id, {
        "content_hash": digest,
        "content_type": content_type,
        "size_bytes": len(data),
        "manifest_hash": manifest.manifest_hash,
    })
    db.commit()
    db.refresh(obj)
    db.refresh(ref)
    db.refresh(manifest)
    return obj, ref, manifest, ledger


def verify_object(db, obj, actor, record=True):
    if obj.status != "ACTIVE":
        return {"status": "MISSING", "evidence_id": obj.id, "reason": "evidence is not active"}
    if not obj.storage_uri:
        return {"status": "MISSING", "evidence_id": obj.id, "reason": "storage reference is missing"}
    try:
        data = _stored_bytes(obj)
    except ValueError:
        return {"status": "UNKNOWN", "evidence_id": obj.id, "reason": "storage reference is invalid"}
    except FileNotFoundError:
        result = {"status": "MISSING", "evidence_id": obj.id, "expected_hash": obj.object_hash}
    except InvalidToken:
        result = {"status": "HASH_MISMATCH", "evidence_id": obj.id, "expected_hash": obj.object_hash, "reason": "encrypted evidence authentication failed"}
    else:
        actual = _hash_bytes(data)
        result = {"status": "VERIFIED" if actual == obj.object_hash else "HASH_MISMATCH", "evidence_id": obj.id, "expected_hash": obj.object_hash, "computed_hash": actual}
    report = db.get(ThreatIntelligenceReport, obj.report_id) if obj.report_id else None
    revision = db.get(ReportRevision, obj.revision_id) if obj.revision_id else None
    if report and revision and record:
        _event(db, "EVIDENCE_VERIFIED", actor, report, revision, obj.id, result)
        db.commit()
    return result


def read_verified(db, obj, actor):
    integrity = verify_object(db, obj, actor)
    if integrity.get("status") != "VERIFIED":
        return integrity, None
    try:
        return integrity, _stored_bytes(obj)
    except (FileNotFoundError, InvalidToken, ValueError):
        return {"status": "UNKNOWN", "evidence_id": obj.id, "reason": "evidence could not be decrypted"}, None


def can_access(obj, principal, admin=False):
    if admin or obj.owner_user_id == principal.user_id:
        return True
    if obj.access_classification != "AUTHORIZED_USERS":
        return False
    try:
        allowed = json.loads(obj.metadata_json or "{}").get("authorized_user_ids", [])
    except (TypeError, ValueError):
        allowed = []
    return principal.user_id in {str(item) for item in allowed}


def serialize_object(db, obj, principal, admin=False):
    verification = verify_object(db, obj, principal.user_id, record=False) if can_access(obj, principal, admin) else {"status": "ACCESS_DENIED", "evidence_id": obj.id}
    metadata = json.loads(obj.metadata_json or "{}")
    return {
        "id": obj.id,
        "report_id": obj.report_id,
        "revision_id": obj.revision_id,
        "object_hash": obj.object_hash,
        "hash_algorithm": obj.hash_algorithm,
        "content_type": obj.content_type,
        "size_bytes": obj.size_bytes,
        "access_classification": obj.access_classification,
        "encryption_status": obj.encryption_status,
        "malware_scan_status": obj.malware_scan_status,
        "malware_scan_provider": obj.malware_scan_provider,
        "malware_scanned_at": obj.malware_scanned_at,
        "ipfs_cid": obj.ipfs_cid,
        "ipfs_status": obj.ipfs_status,
        "retention_expires_at": obj.retention_expires_at,
        "status": obj.status,
        "metadata": {k: v for k, v in metadata.items() if k != "filename"},
        "created_at": obj.created_at,
        "integrity": verification,
    }


def manifest_details(db, report, revision_id, actor):
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision:
        raise LookupError("revision not found")
    rows = db.query(EvidenceManifest).filter_by(revision_id=revision.id).order_by(EvidenceManifest.version.desc()).all()
    return [{"id": x.id, "report_id": x.report_id, "revision_id": x.revision_id, "version": x.version, "manifest_hash": x.manifest_hash, "hash_algorithm": x.hash_algorithm, "canonical_manifest": x.canonical_manifest, "created_by": x.created_by, "created_at": x.created_at} for x in rows]


def verify_manifest(db, report, revision_id, version=None):
    revision = db.query(ReportRevision).filter_by(id=revision_id, report_id=report.id).first()
    if not revision:
        raise LookupError("revision not found")
    query = db.query(EvidenceManifest).filter_by(revision_id=revision.id)
    row = query.filter_by(version=version).first() if version is not None else query.order_by(EvidenceManifest.version.desc()).first()
    if not row:
        return {"status": "MISSING", "revision_id": revision.id}
    actual = hashlib.sha256((MANIFEST_DOMAIN + ":" + row.canonical_manifest).encode("utf-8")).hexdigest()
    return {"status": "VERIFIED" if actual == row.manifest_hash else "HASH_MISMATCH", "manifest_id": row.id, "revision_id": row.revision_id, "version": row.version, "stored_hash": row.manifest_hash, "computed_hash": actual}


def pin_to_ipfs(db, obj, actor):
    if not settings.evidence_ipfs_pin_url:
        obj.ipfs_status = "UNAVAILABLE"
        db.commit()
        return {"status": "UNAVAILABLE", "evidence_id": obj.id, "reason": "IPFS pinning provider is not configured"}
    try:
        raw = _safe_relative(obj.storage_uri).read_bytes()
        headers = {"Authorization": f"Bearer {settings.evidence_ipfs_auth_token}"} if settings.evidence_ipfs_auth_token else {}
        if "/api/v0/add" in settings.evidence_ipfs_pin_url:
            response = httpx.post(
                settings.evidence_ipfs_pin_url,
                files={"file": ("evidence.bin", raw, "application/octet-stream")},
                headers=headers,
                timeout=settings.evidence_ipfs_timeout_seconds,
            )
        else:
            response = httpx.post(settings.evidence_ipfs_pin_url, content=raw, headers=headers, timeout=settings.evidence_ipfs_timeout_seconds)
        response.raise_for_status()
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = json.loads(response.text.splitlines()[-1]) if response.text.strip() else {}
        cid = body.get("IpfsHash") or body.get("cid") or body.get("CID") or body.get("Hash")
        if not cid:
            raise ValueError("IPFS provider did not return a CID")
        obj.ipfs_cid = str(cid)[:255]
        obj.ipfs_status = "PINNED"
        report = db.get(ThreatIntelligenceReport, obj.report_id)
        revision = db.get(ReportRevision, obj.revision_id)
        if report and revision:
            _event(db, "EVIDENCE_IPFS_PINNED", actor, report, revision, obj.id, {"cid": obj.ipfs_cid, "content_hash": obj.object_hash})
        db.commit()
        return {"status": "PINNED", "evidence_id": obj.id, "cid": obj.ipfs_cid}
    except Exception as exc:
        obj.ipfs_status = "UNAVAILABLE"
        db.commit()
        return {"status": "UNAVAILABLE", "evidence_id": obj.id, "reason": type(exc).__name__}


def cleanup_expired(db, actor="system"):
    now = _now()
    rows = db.query(EvidenceObject).filter(EvidenceObject.retention_expires_at <= now, EvidenceObject.status == "ACTIVE").all()
    removed = []
    for obj in rows:
        try:
            if obj.storage_uri:
                path = _safe_relative(obj.storage_uri)
                if path.exists():
                    path.unlink()
        except (OSError, ValueError):
            pass
        report = db.get(ThreatIntelligenceReport, obj.report_id) if obj.report_id else None
        revision = db.get(ReportRevision, obj.revision_id) if obj.revision_id else None
        if report and revision:
            _event(db, "EVIDENCE_RETENTION_DELETED", actor, report, revision, obj.id, {"content_hash": obj.object_hash})
        obj.storage_uri = None
        obj.status = "DELETED"
        removed.append(obj.id)
    db.commit()
    return {"deleted_count": len(removed), "evidence_ids": removed, "checked_at": now}
