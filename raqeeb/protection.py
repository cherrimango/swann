"""Threat distribution: signed, versioned protection packages, the global-block policy, expiry and rollback.

Policy (enforced here, not in the UI):
  * Only accounts with the `approve_block` permission can block globally.
  * Only threats in status `confirmed_malicious` can be blocked globally. Citizen reports never block anyone else.
  * Popular domains, free-hosting platforms and URL shorteners are blocked at URL level, never the whole domain.
  * Every global block has an expiry (default 30 days) and is re-evaluated; any version can be rolled back.
"""
import base64
import json
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .auth import can
from .db import LOCK, ROOT, db, one, rows
from .engine import TOP_LEGIT
from .intel import add_history, get
from .urlparse import FREE_HOSTING, SHORTENERS, parse, under_any

KEY_FILE = ROOT / "data" / "keys" / "protection_ed25519.pem"
DEFAULT_EXPIRY_DAYS = int(os.environ.get("RAQEEB_BLOCK_EXPIRY_DAYS", "30"))


class PolicyError(Exception):
    pass


def _key() -> Ed25519PrivateKey:
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        return serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
    k = Ed25519PrivateKey.generate()
    KEY_FILE.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return k


def public_key_b64() -> str:
    raw = _key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(package: dict, pub_b64: str | None = None) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64 or public_key_b64()))
    try:
        pub.verify(base64.b64decode(package["signature"]), canonical(package["payload"]))
        return True
    except Exception:  # noqa: BLE001
        return False


def scope_for(t: dict) -> tuple[str, str]:
    """Decide what exactly to block for a threat: (rule type, value)."""
    if t["indicator_type"] == "phone":
        return "phone", t["normalized"]
    p = parse(t["normalized"] if "://" in t["normalized"] else "http://" + t["normalized"])
    shared = (p.registered_domain in TOP_LEGIT or under_any(p.host, FREE_HOSTING) or p.registered_domain in SHORTENERS)
    has_path = bool(p.path.strip("/") or p.query)
    if shared and has_path:
        return "url", t["normalized"]
    if shared:
        return "host", p.host.removeprefix("www.")  # e.g. one *.vercel.app site, never vercel.app itself
    return "domain", p.host.removeprefix("www.")


def current_rules() -> list[dict]:
    now = time.time()
    out = []
    for t in rows(db().execute("SELECT * FROM threats WHERE block_status='global'")):
        if t["block_expires"] and t["block_expires"] < now:
            continue
        kind, value = scope_for(t)
        out.append({"type": kind, "value": value, "threat_id": t["id"], "severity": t["severity"], "brand": t["brand"] or "",
                    "category": t["category"], "expires": t["block_expires"]})
    seen = {r["value"] for r in out}
    for b in rows(db().execute("SELECT * FROM blocklist")):  # 1.0 officer blocks kept working
        if b["domain"] not in seen:
            out.append({"type": "domain", "value": b["domain"], "threat_id": None, "severity": "high", "brand": b["brand"] or "",
                        "category": "phishing_website", "expires": None})
    return sorted(out, key=lambda r: (r["type"], r["value"]))


def publish(actor: str, notes: str = "") -> dict:
    with LOCK:
        rules = current_rules()
        last = one(db().execute("SELECT MAX(version) v FROM protection_versions"))["v"] or 0
        payload = {"version": last + 1, "created": round(time.time(), 3), "rules": rules}
        sig = base64.b64encode(_key().sign(canonical(payload))).decode()
        db().execute("INSERT INTO protection_versions (version, created, published_by, rules, signature, notes) VALUES (?,?,?,?,?,?)",
                     (payload["version"], payload["created"], actor, json.dumps(rules), sig, notes[:300]))
        db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,?,?)",
                     ("protection_publish", json.dumps({"version": payload["version"], "rules": len(rules), "notes": notes}), time.time(), actor))
    return {"payload": payload, "signature": sig}


def latest() -> dict:
    v = one(db().execute("SELECT * FROM protection_versions ORDER BY version DESC LIMIT 1"))
    if not v:
        return publish("system", "initial empty package")
    return {"payload": {"version": v["version"], "created": v["created"], "rules": json.loads(v["rules"])}, "signature": v["signature"]}


def versions(limit=30) -> list[dict]:
    out = rows(db().execute("SELECT version, created, published_by, notes, rolled_back, rules FROM protection_versions ORDER BY version DESC LIMIT ?", (limit,)))
    for v in out:
        v["rule_count"] = len(json.loads(v.pop("rules")))
    return out


def domain_rules_for_dns() -> list[str]:
    return sorted({r["value"] for r in latest()["payload"]["rules"] if r["type"] in ("domain", "host")})


def global_block(tid: str, actor: dict, expiry_days: int | None = None, note: str = "") -> dict:
    if not can(actor["role"], "approve_block"):
        raise PolicyError("Your role can’t approve global blocking")
    t = get(tid)
    if not t:
        raise PolicyError("Threat not found")
    if t["status"] != "confirmed_malicious":
        raise PolicyError("Only threats confirmed malicious can be blocked for everyone. Verify and confirm it first.")
    days = expiry_days or DEFAULT_EXPIRY_DAYS
    kind, value = scope_for(t)
    expires = time.time() + days * 86400
    db().execute("UPDATE threats SET block_status='global', block_scope=?, block_expires=? WHERE id=?", (kind, expires, tid))
    add_history(tid, {"event": "global_block", "by": actor["email"], "scope": kind, "value": value, "expiry_days": days, "note": note[:300]})
    return publish(actor["email"], f"Block {value} ({kind}) for {days} days: {tid}")


def unblock(tid: str, actor: dict, reason: str = "") -> dict:
    if not can(actor["role"], "approve_block"):
        raise PolicyError("Your role can’t change global blocking")
    return release(tid, actor["email"], reason)


def release(tid: str, actor_email: str, reason: str) -> dict:
    """Lift a global block. Lifting is always safe, so any verified reviewer marking a false positive triggers it."""
    db().execute("UPDATE threats SET block_status='none' WHERE id=?", (tid,))
    add_history(tid, {"event": "unblock", "by": actor_email, "note": reason[:300]})
    return publish(actor_email, f"Unblock {tid}: {reason}")


def rollback(actor: dict) -> dict:
    """Emergency rollback: undo the latest published version by restoring the previous rule set."""
    if not can(actor["role"], "rollback"):
        raise PolicyError("Your role can’t roll back protection updates")
    vs = rows(db().execute("SELECT * FROM protection_versions WHERE rolled_back=0 ORDER BY version DESC LIMIT 2"))
    if not vs:
        raise PolicyError("Nothing has been published yet")
    newest = vs[0]
    prev = vs[1] if len(vs) > 1 else {"version": 0, "rules": "[]"}
    keep = {r["threat_id"] for r in json.loads(prev["rules"]) if r["threat_id"]}
    for r in json.loads(newest["rules"]):
        if r["threat_id"] and r["threat_id"] not in keep:
            db().execute("UPDATE threats SET block_status='rolled_back' WHERE id=?", (r["threat_id"],))
            add_history(r["threat_id"], {"event": "rollback", "by": actor["email"], "version": newest["version"]})
    db().execute("UPDATE protection_versions SET rolled_back=1 WHERE version=?", (newest["version"],))
    return publish(actor["email"], f"Emergency rollback of v{newest['version']} to v{prev['version']} rules")


def expire_due() -> dict | None:
    """Expire blocks past their date (they return to review). Publishes a new version only if something changed."""
    now = time.time()
    due = rows(db().execute("SELECT id FROM threats WHERE block_status='global' AND block_expires IS NOT NULL AND block_expires < ?", (now,)))
    if not due:
        return None
    for t in due:
        db().execute("UPDATE threats SET block_status='expired', status='under_review' WHERE id=?", (t["id"],))
        add_history(t["id"], {"event": "block_expired", "by": "system", "note": "returned to review for re-evaluation"})
    return publish("system", f"Expired {len(due)} blocks for re-evaluation")


def check_value(value: str, kind: str = "url") -> dict | None:
    """Is a URL / phone covered by the current published package? Used by the phone app and the API."""
    rules = latest()["payload"]["rules"]
    if kind == "phone":
        from .intel import normalize_phone
        n = normalize_phone(value)
        return next((r for r in rules if r["type"] == "phone" and r["value"] == n), None)
    p = parse(value)
    host = p.host.removeprefix("www.")
    norm = host + (p.path.rstrip("/") or "") + (f"?{p.query}" if p.query else "")
    for r in rules:
        if r["type"] == "url" and norm.startswith(r["value"]):
            return r
        if r["type"] in ("domain", "host") and (host == r["value"] or host.endswith("." + r["value"])):
            return r
    return None
