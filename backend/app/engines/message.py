import re
import uuid
from backend.app.engines.ml import predict
from backend.app.services.llm import explain_message
from backend.app.engines.message_intelligence import analyze_indicators

URL_RE = re.compile(r"https?://[^\s<>]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")

def analyze_message(text: str, brands=None, email_providers=None):
    lower = text.lower(); evidence=[]; score=0
    patterns = [(r"urgent|immediately|within \d+ hours|act now", "Urgency-based pressure", "medium", 12), (r"gift card|wire transfer|crypto|bitcoin|otp|one[- ]time password", "Payment or credential request", "high", 25), (r"verify your account|suspended|unusual activity|security alert", "Account impersonation language", "medium", 15), (r"keep this confidential|do not tell anyone", "Isolation or secrecy language", "medium", 12)]
    for pattern, message, severity, points in patterns:
        if re.search(pattern, lower):
            evidence.append({"issue":message,"severity":severity,"state":"suspicious","evidence":pattern}); score += points
    ml_result=predict(text)
    model_score=round(ml_result["malicious_probability"]*100) if ml_result.get("available") else 0
    combined_score=max(min(score,100),model_score)
    classification="high risk — not confirmed fraud" if combined_score>=75 else "suspicious — not confirmed fraud" if combined_score>=35 else "low risk — no confirmed fraud"
    deterministic={"classification":classification,"score":combined_score,"confidence":"high" if model_score>=75 else "medium" if evidence else "low","evidence":evidence}
    indicators={"urls":URL_RE.findall(text),"emails":EMAIL_RE.findall(text),"phones":PHONE_RE.findall(text)}
    result={**deterministic,"indicators":indicators,"recommendations":["Do not click links or disclose credentials","Verify the sender through an independently known channel","Contact the organisation using its official website or phone number"],"limitation":"A model score is a risk estimate, not proof of fraud; extracted URLs should be scanned separately.","ml":ml_result,"correlation_id":f"msg-{uuid.uuid4().hex}"}
    result["indicator_intelligence"] = analyze_indicators(indicators, brands=brands, email_providers=email_providers)
    result["llm"]=explain_message(text,deterministic,indicators,result["correlation_id"])
    return result
