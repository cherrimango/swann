"""Request-level security: who is calling, what their role allows, and how often they may call."""
from fastapi import Depends, HTTPException, Request

from raqeeb import auth
from raqeeb.security import LIMITS, ip_hash, limiter


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def token_of(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return None


def current_user(request: Request) -> dict | None:
    return auth.user_for_token(token_of(request))


def require_user(user: dict | None = Depends(current_user)) -> dict:
    if not user:
        raise HTTPException(401, "Sign in to continue")
    return user


def require(perm: str):
    def dep(user: dict = Depends(require_user)) -> dict:
        if not auth.can(user["role"], perm):
            raise HTTPException(403, "Your role doesn’t allow this action")
        return user
    return dep


def require_official(user: dict = Depends(require_user)) -> dict:
    if user["role"] not in auth.OFFICIAL_ROLES:
        raise HTTPException(403, "RAQEEB Command is for authorised officials")
    return user


def rate(name: str):
    limit, window = LIMITS[name]

    def dep(request: Request, user: dict | None = Depends(current_user)):
        key = f"{name}:{user['id'] if user else ip_hash(client_ip(request))}"
        if not limiter.allow(key, limit, window):
            raise HTTPException(429, "Too many requests. Wait a few minutes and try again.")
    return dep
