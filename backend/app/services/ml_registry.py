"Reproducible dataset/model registry helpers with fail-closed artifact handling."
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DATASET_ROOT = (ROOT / "dataset").resolve()
MODEL_ROOT = (ROOT / "models").resolve()
POINTER = MODEL_ROOT / "production_pointer.json"

def _safe_dataset(path: str) -> Path:
    candidate = (DATASET_ROOT / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if DATASET_ROOT not in candidate.parents and candidate != DATASET_ROOT: raise ValueError("dataset must be inside the workspace dataset directory")
    if not candidate.is_file(): raise FileNotFoundError("dataset_not_found")
    return candidate

def _safe_artifact(path: str) -> Path:
    relative = Path(path)
    base = ROOT if relative.parts and relative.parts[0].lower() == "models" else MODEL_ROOT
    candidate = (base / relative).resolve() if not relative.is_absolute() else relative.resolve()
    if MODEL_ROOT not in candidate.parents or not candidate.is_file(): raise ValueError("artifact must be an existing file inside the models directory")
    return candidate

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return digest.hexdigest()

def validate_dataset(path: str, max_rows: int = 500000) -> dict[str, Any]:
    file_path = _safe_dataset(path); checksum = sha256_file(file_path); rows=0; empty=0; malformed=0; duplicates=0; inconsistent=0; labels=Counter(); seen={}
    csv.field_size_limit(50 * 1024 * 1024)
    with file_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "label" not in reader.fieldnames: raise ValueError("dataset_requires_label_column")
        content_column = "body" if "body" in reader.fieldnames else "text" if "text" in reader.fieldnames else None
        if not content_column: raise ValueError("dataset_requires_body_or_text_column")
        for row in reader:
            if rows >= max_rows: break
            rows += 1; content=(row.get(content_column) or "").strip(); raw_label=(row.get("label") or "").strip()
            if not content: empty += 1
            try: label=int(float(raw_label)); labels[str(label)] += 1
            except (TypeError, ValueError): malformed += 1; continue
            if label not in (0,1): malformed += 1
            digest=hashlib.sha256(content.lower().encode()).hexdigest()
            if digest in seen:
                duplicates += 1
                if seen[digest] != label: inconsistent += 1
            else: seen[digest] = label
    total=max(rows,1); minority=min(labels.values()) if labels else 0; majority=max(labels.values()) if labels else 0
    quality={"rows_read": rows, "empty_content": empty, "malformed_records": malformed, "duplicate_records": duplicates, "inconsistent_duplicate_labels": inconsistent, "class_imbalance_ratio": round(minority / majority, 4) if majority else None, "leakage_warning": duplicates > 0 or inconsistent > 0, "stratification_possible": len(labels) >= 2 and minority >= 2}
    validation="VALID" if rows and not empty and not malformed and not inconsistent and len(labels) >= 2 else "INVALID"
    try: display_path = str(file_path.relative_to(DATASET_ROOT))
    except ValueError: display_path = file_path.name
    return {"path": display_path, "checksum": checksum, "record_count": rows, "class_distribution": dict(labels), "quality": quality, "validation_status": validation}

def artifact_metadata(path: str) -> dict[str, Any]:
    file_path=_safe_artifact(path)
    result={"path": str(file_path.relative_to(ROOT)), "checksum": sha256_file(file_path), "size_bytes": file_path.stat().st_size}
    try:
        import joblib
        bundle=joblib.load(file_path)
        result.update({"name": bundle.get("model_name", file_path.stem), "model_version": bundle.get("model_version"), "dataset_version": bundle.get("dataset_version"), "metrics": bundle.get("metrics", {}), "feature_config": bundle.get("feature_config", {}), "hyperparameters": bundle.get("hyperparameters", {})})
    except Exception as exc: result["inspection_error"] = type(exc).__name__
    return result

def production_artifact() -> Path:
    if POINTER.exists():
        try:
            target=_safe_artifact(json.loads(POINTER.read_text()).get("artifact_location", "")); return target
        except Exception:
            pass
    return MODEL_ROOT / "phishing_message_model.joblib"
