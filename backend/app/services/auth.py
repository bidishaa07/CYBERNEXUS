"""OIDC-compatible JWT/JWKS validation and identity synchronization."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import jwt
from fastapi import HTTPException, Header, Cookie, Depends
from jwt import PyJWKClient
from backend.app.core.config import settings
from backend.app.models.models import AppUser, LegacyIdentityLink
from backend.app.db.session import get_db

_jwks: PyJWKClient | None = None

@dataclass
class Principal:
    user_id: str
    external_subject: str | None
    role: str
    authenticated: bool
    legacy_ids: tuple[str, ...] = ()

def _admin_roles() -> set[str]:
    return {x.strip() for x in settings.oidc_admin_roles.split(",") if x.strip()}

def _roles(claims: dict[str, Any]) -> set[str]:
    roles = set(claims.get("roles") or [])
    roles.update(claims.get("groups") or [])
    roles.update((claims.get("realm_access") or {}).get("roles") or [])
    return {str(x) for x in roles}

def verify_token(token: str) -> dict[str, Any]:
    if not settings.oidc_issuer_url or not settings.oidc_audience or not (settings.oidc_jwks_url or settings.oidc_issuer_url):
        raise HTTPException(503, "OIDC authentication is not configured")
    global _jwks
    try:
        _jwks = _jwks or PyJWKClient(settings.oidc_jwks_url or settings.oidc_issuer_url.rstrip("/") + "/.well-known/jwks.json")
        key = _jwks.get_signing_key_from_jwt(token)
        return jwt.decode(token, key.key, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"], audience=settings.oidc_audience, issuer=settings.oidc_issuer_url, options={"require": ["exp", "sub"]})
    except Exception as exc:
        raise HTTPException(401, "Invalid or expired authentication token") from exc

def sync_user(db, claims: dict[str, Any]) -> Principal:
    subject = str(claims["sub"]); roles = _roles(claims); role = "admin" if roles & _admin_roles() else "user"; now = datetime.now(timezone.utc)
    user = db.query(AppUser).filter(AppUser.external_subject == subject).first()
    if not user: user = AppUser(external_subject=subject, email=claims.get("email"), display_name=claims.get("name") or claims.get("preferred_username"), role=role, account_status="active", last_login_at=now); db.add(user); db.flush()
    else: user.email=claims.get("email", user.email); user.display_name=claims.get("name") or claims.get("preferred_username") or user.display_name; user.role=role; user.last_login_at=now
    if user.account_status != "active": raise HTTPException(403, "Account is not active")
    legacy_ids = tuple(link.legacy_user_id for link in db.query(LegacyIdentityLink).filter(LegacyIdentityLink.external_subject == subject).all())
    return Principal(user_id=f"user:{user.id}", external_subject=subject, role=user.role, authenticated=True, legacy_ids=legacy_ids)

def principal_from_headers(db, authorization: str | None, cookie: str | None, legacy_header: str | None) -> Principal:
    token = authorization.removeprefix("Bearer ").strip() if authorization and authorization.startswith("Bearer ") else cookie
    if token:
        return sync_user(db, verify_token(token))
    if settings.auth_required or settings.environment.lower() == "production":
        raise HTTPException(401, "Authentication required")
    # Development compatibility only. This branch is disabled in production.
    legacy = (legacy_header or "anonymous").strip()[:160] or "anonymous"
    return Principal(user_id=legacy, external_subject=None, role="user", authenticated=False, legacy_ids=(legacy,))

def get_current_principal(authorization: str | None = Header(default=None), digital_trust_session: str | None = Cookie(default=None), x_user_id: str | None = Header(default=None, alias="X-User-ID"), db=Depends(get_db)) -> Principal:
    return principal_from_headers(db, authorization, digital_trust_session, x_user_id)
