from pathlib import Path
import joblib

MODEL_PATH = Path(__file__).resolve().parents[3] / "models" / "phishing_message_model.joblib"
def status():
    if not MODEL_PATH.exists(): return {"available":False,"message":"No trained model found. Run the training command."}
    try:
        bundle=joblib.load(MODEL_PATH); return {"available":True,"model":bundle.get("model_name"),"metrics":bundle.get("metrics",{}),"trained_rows":bundle.get("trained_rows",0)}
    except Exception as exc: return {"available":False,"message":type(exc).__name__}
def predict(text: str):
    if not MODEL_PATH.exists(): return {"available":False,"reason":"model_not_trained"}
    try:
        bundle=joblib.load(MODEL_PATH); value=float(bundle["pipeline"].predict_proba([text])[0][1]); return {"available":True,"malicious_probability":round(value,4),"prediction":int(value>=.5),"model":bundle.get("model_name")}
    except Exception as exc: return {"available":False,"reason":type(exc).__name__}
