"""Redis-backed cache with explicit development-only local fallback."""
import json
import time
from typing import Any
from backend.app.core.config import settings

try:
    import redis
except ImportError:  # pragma: no cover
    redis = None

_local: dict[str, tuple[float, Any]] = {}

def _client():
    if not settings.redis_url or redis is None: return None
    return redis.Redis.from_url(settings.redis_url, socket_timeout=settings.redis_timeout_seconds, decode_responses=True)

def get(key: str) -> Any:
    key = f"{settings.redis_namespace}:{key}"
    client = _client()
    if client:
        value = client.get(key); return json.loads(value) if value else None
    if settings.environment.lower() == "production": raise RuntimeError("Redis is required in production")
    item = _local.get(key)
    if not item or item[0] <= time.time(): _local.pop(key, None); return None
    return item[1]

def set(key: str, value: Any, ttl: int) -> None:
    key = f"{settings.redis_namespace}:{key}"
    client = _client()
    if client:
        client.setex(key, ttl, json.dumps(value, default=str)); return
    if settings.environment.lower() == "production": raise RuntimeError("Redis is required in production")
    _local[key] = (time.time() + ttl, value)

def health() -> dict[str, Any]:
    if not settings.redis_url: return {"status": "NOT_CONFIGURED", "backend": "local-development" if settings.environment != "production" else "missing"}
    if redis is None: return {"status": "UNAVAILABLE", "error": "redis package is not installed"}
    try: _client().ping(); return {"status": "CONNECTED", "backend": "redis"}
    except Exception as exc: return {"status": "UNAVAILABLE", "backend": "redis", "error": type(exc).__name__}
