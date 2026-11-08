import httpx
from backend.app.services import llm


class FakeResponse:
    def __init__(self, status_code=200, body=None, headers=None, text=""):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.text = text

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def provider(name="primary", provider_name="Test", key="key", model="model"):
    return {"name": name, "provider": provider_name, "key": key, "model": model, "base_url": "https://llm.test/v1", "timeout": 5, "privacy": True}


def test_successful_completion(monkeypatch):
    llm.reset_circuits()
    monkeypatch.setattr(llm, "_provider_configs", lambda: [provider()])
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: FakeResponse(body={"choices": [{"message": {"content": "Evidence-based explanation"}}]}))
    result = llm.explain_message("hello", {"classification": "low risk", "score": 5, "evidence": []}, {})
    assert result["available"] is True
    assert result["status"] == "CONNECTED"
    assert result["explanation"] == "Evidence-based explanation"


def test_timeout_returns_template_fallback(monkeypatch):
    llm.reset_circuits()
    monkeypatch.setattr(llm, "_provider_configs", lambda: [provider()])
    monkeypatch.setattr(llm.settings, "llm_max_retries", 0)
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: (_ for _ in ()).throw(httpx.ReadTimeout("slow")))
    result = llm.explain_message("urgent payment", {"classification": "high risk", "score": 80, "evidence": [{"issue": "Payment request"}]}, {})
    assert result["status"] == "UNAVAILABLE"
    assert result["fallback_type"] == "template"
    assert "Payment request" in result["explanation"]


def test_authentication_failure_is_not_retried(monkeypatch):
    llm.reset_circuits()
    monkeypatch.setattr(llm, "_provider_configs", lambda: [provider()])
    calls = []
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: (calls.append(1) or FakeResponse(status_code=401, text="unauthorized")))
    result = llm.explain_message("hello", {"classification": "unknown", "score": 0, "evidence": []}, {})
    assert result["failures"][0]["status"] == "INVALID_CREDENTIALS"
    assert len(calls) == 1


def test_secondary_provider_is_used_only_when_configured(monkeypatch):
    llm.reset_circuits()
    monkeypatch.setattr(llm, "_provider_configs", lambda: [provider(), provider("secondary", "Fallback", "fallback-key", "fallback-model")])
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs["headers"]["Authorization"])
        if len(calls) == 1:
            return FakeResponse(status_code=503, text="temporary")
        return FakeResponse(body={"choices": [{"message": {"content": "Fallback explanation"}}]})

    monkeypatch.setattr(llm.settings, "llm_max_retries", 0)
    monkeypatch.setattr(llm.httpx, "post", post)
    result = llm.explain_message("hello", {"classification": "unknown", "score": 0, "evidence": []}, {})
    assert result["available"] is True
    assert result["fallback_used"] is True
    assert result["provider"] == "Fallback"
    assert calls == ["Bearer key", "Bearer fallback-key"]
