"""Accounts, sessions and role-based permissions.

Passwords: scrypt (N=2^14, r=8, p=1) with a random salt. Session tokens: 256-bit random, stored only as SHA-256
hashes, sent as an HttpOnly cookie (browsers) or a Bearer token (Android / API clients).
"""
import hashlib
import hmac
import os
import re
import secrets
import time

from .db import LOCK, db, one, rows

ROLES = {
    "super_admin": "Super Administrator",
    "police_admin": "Police Administrator",
    "cyber_analyst": "Cybercrime Analyst",
    "investigation_officer": "Investigation Officer",
    "intel_analyst": "Intelligence Analyst",
    "supervisor": "Read-only Supervisor",
    "citizen": "Citizen",
}
OFFICIAL_ROLES = set(ROLES) - {"citizen"}

PERMISSIONS = {
    "view_command": OFFICIAL_ROLES,
    "view_investigations": OFFICIAL_ROLES,
    "verify_threat": {"super_admin", "police_admin", "cyber_analyst", "intel_analyst"},
    "edit_investigation": {"super_admin", "police_admin", "cyber_analyst", "investigation_officer", "intel_analyst"},
    "approve_threat": {"super_admin", "police_admin"},  # official approval: separate from analyst verification
    "approve_block": {"super_admin", "police_admin"},
    "manage_registry": {"super_admin", "police_admin"},
    "rollback": {"super_admin", "police_admin"},
    "run_hunt": {"super_admin", "police_admin", "cyber_analyst", "intel_analyst"},
    "view_evidence": {"super_admin", "police_admin", "cyber_analyst", "investigation_officer", "intel_analyst"},
    "view_audit": {"super_admin", "police_admin", "supervisor"},
    "manage_users": {"super_admin"},
    "review_community": {"super_admin", "police_admin", "intel_analyst"},
}

SESSION_TTL = {"official": 12 * 3600, "citizen": 30 * 86400}
EMIRATES = ["Abu Dhabi", "Dubai", "Sharjah", "Ajman", "Umm Al Quwain", "Ras Al Khaimah", "Fujairah"]


def can(role: str, perm: str) -> bool:
    return role in PERMISSIONS.get(perm, set())


def permissions_for(role: str) -> list[str]:
    return sorted(p for p, rs in PERMISSIONS.items() if role in rs)


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        test = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(test.hex(), dk)
    except (ValueError, TypeError):
        return False


def anonymous_name() -> str:
    return f"Guardian-{secrets.randbelow(9000) + 1000}"


class AuthError(Exception):
    pass


def validate_new(email: str, password: str):
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,24}", email.lower()):
        raise AuthError("Enter a valid email address")
    if len(password) < 8:
        raise AuthError("Use a password of at least 8 characters")


def create_user(email, password, role="citizen", display_name=None, emirate=None, public_rank=True) -> dict:
    if role not in ROLES:
        raise AuthError("Unknown role")
    validate_new(email, password)
    if emirate and emirate not in EMIRATES:
        raise AuthError("Choose one of the seven emirates")
    name = (display_name or "").strip()[:40] or anonymous_name()
    with LOCK:
        if one(db().execute("SELECT id FROM users WHERE email = ?", (email.lower(),))):
            raise AuthError("An account with this email already exists")
        cur = db().execute(
            "INSERT INTO users (email, pw_hash, role, display_name, emirate, public_rank, created) VALUES (?,?,?,?,?,?,?)",
            (email.lower(), hash_password(password), role, name, emirate, int(bool(public_rank)), time.time()))
    return get_user(cur.lastrowid)


def get_user(uid) -> dict | None:
    u = one(db().execute("SELECT * FROM users WHERE id = ?", (uid,)))
    if u:
        u.pop("pw_hash", None)
        u["role_name"] = ROLES.get(u["role"], u["role"])
        u["permissions"] = permissions_for(u["role"])
    return u


def login(email: str, password: str, ip: str = "") -> tuple[str, dict]:
    u = one(db().execute("SELECT * FROM users WHERE email = ?", ((email or "").lower(),)))
    if not u or u["disabled"] or not verify_password(password or "", u["pw_hash"]):
        raise AuthError("Email or password is incorrect")
    token = secrets.token_urlsafe(32)
    ttl = SESSION_TTL["official" if u["role"] in OFFICIAL_ROLES else "citizen"]
    db().execute("INSERT INTO sessions (token_hash, user_id, created, expires, ip) VALUES (?,?,?,?,?)",
                 (_th(token), u["id"], time.time(), time.time() + ttl, ip))
    return token, get_user(u["id"])


def logout(token: str):
    db().execute("DELETE FROM sessions WHERE token_hash = ?", (_th(token),))


def user_for_token(token: str | None) -> dict | None:
    if not token:
        return None
    s = one(db().execute("SELECT * FROM sessions WHERE token_hash = ?", (_th(token),)))
    if not s or s["expires"] < time.time():
        return None
    u = get_user(s["user_id"])
    return u if u and not u["disabled"] else None


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def list_users() -> list[dict]:
    out = rows(db().execute("SELECT id, email, role, display_name, emirate, reputation, disabled, created FROM users ORDER BY id"))
    for u in out:
        u["role_name"] = ROLES.get(u["role"], u["role"])
    return out


def bootstrap() -> list[tuple[str, str, str]] | None:
    """First run: create one official account per role with random passwords (or RAQEEB_ADMIN_PASSWORD for the
    super admin) and write them to data/first_run_credentials.txt. Returns the created accounts."""
    if one(db().execute("SELECT id FROM users WHERE role = 'super_admin'")):
        return None
    created = []
    for role in ["super_admin", "police_admin", "cyber_analyst", "investigation_officer", "intel_analyst", "supervisor"]:
        email = os.environ.get("RAQEEB_ADMIN_EMAIL", "admin@raqeeb.local") if role == "super_admin" else f"{role.replace('_', '.')}@raqeeb.local"
        pw = os.environ.get("RAQEEB_ADMIN_PASSWORD") if role == "super_admin" and os.environ.get("RAQEEB_ADMIN_PASSWORD") else secrets.token_urlsafe(9)
        create_user(email, pw, role=role, display_name=ROLES[role])
        created.append((ROLES[role], email, pw))
    from . import db as _dbm
    f = _dbm.DB_PATH.parent / "first_run_credentials.txt"
    f.write_text("RAQEEB Command accounts created on first run. Change these passwords before any real use.\n\n" +
                 "\n".join(f"{r:<24} {e:<40} {p}" for r, e, p in created) + "\n", encoding="utf-8")
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return created
