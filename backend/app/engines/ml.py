from pathlib import Path
import joblib
from backend.app.services.ml_registry import production_artifact

MODEL_PATH = Path(__file__).resolve().parents[3] / "models" / "phishing_message_model.joblib"
def status():
    active_path = production_artifact()
    if not active_path.exists(): return {"available":False,"message":"No trained model found. Run the training command."}
    try:
        bundle=joblib.load(active_path); return {"available":True,"model":bundle.get("model_name"),"model_version":bundle.get("model_version") or bundle.get("model_name"),"dataset_version":bundle.get("dataset_version"),"metrics":bundle.get("metrics",{}),"trained_rows":bundle.get("trained_rows",0),"artifact":str(active_path)}
    except Exception as exc: return {"available":False,"message":type(exc).__name__}
def predict(text: str):
    active_path = production_artifact()
    if not active_path.exists(): return {"available":False,"reason":"model_not_trained"}
    try:
        bundle=joblib.load(active_path); value=float(bundle["pipeline"].predict_proba([text])[0][1]); return {"available":True,"malicious_probability":round(value,4),"prediction":int(value>=.5),"model":bundle.get("model_version") or bundle.get("model_name"),"model_name":bundle.get("model_name"),"dataset_version":bundle.get("dataset_version")}
    except Exception as exc: return {"available":False,"reason":type(exc).__name__}
