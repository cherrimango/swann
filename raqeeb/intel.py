"""Threat Intelligence Centre: one record per normalized indicator, whatever channel it was seen on."""
import json
import re
import time

from .db import LOCK, db, one, rows
from .urlparse import parse

CATEGORIES = {
    "phishing_website": "Phishing website", "fraud_ad": "Fraudulent advertisement", "fake_social": "Fake social media account",
    "scam_phone": "Scam phone number", "sms": "Fraudulent SMS", "email": "Scam email", "qr": "Malicious QR code",
    "fake_payment": "Fake payment portal", "fake_gov": "Fake government website", "fake_bank": "Fake banking website",
    "fraud_app": "Fraudulent mobile app", "impersonation": "Impersonation campaign", "invest_job": "Investment or employment scam",
    "delivery_customs": "Fake delivery or customs notice", "other": "Other suspicious activity",
}
# Threat verification statuses (citizen reports use the same vocabulary)
STATUSES = ["new", "analysing", "under_review", "community_corroborated", "analyst_verified", "confirmed_malicious",
            "rejected", "duplicate", "false_positive", "resolved"]
STATUS_LABELS = {
    "new": "Newly discovered", "analysing": "AI analysis in progress", "under_review": "Under investigation",
    "community_corroborated": "Community corroborated", "analyst_verified": "Analyst verified",
    "confirmed_malicious": "Officially approved", "rejected": "Rejected", "duplicate": "Duplicate",
    "false_positive": "False positive", "resolved": "Resolved",
}
VERIFIED = {"analyst_verified", "confirmed_malicious"}
SECTOR_CATEGORY = {"government_services": "fake_gov", "police_traffic": "fake_gov", "identity_visa": "fake_gov",
                   "customs": "delivery_customs", "digital_identity": "fake_gov", "banking": "fake_bank",
                   "delivery": "delivery_customs", "transport_tolls": "fake_payment", "employment": "invest_job"}

PHONE_RX = re.compile(r"(?<![\w/])(?:\+|00)?\d[\d \-()]{6,16}\d(?![\w/])")
EMAIL_RX = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+\b")


def normalize_phone(raw: str) -> str | None:
    """Return E.164 (+971...) for UAE local formats (050..., 02..., 5XXXXXXXX) and international numbers."""
    d = re.sub(r"[^\d+]", "", raw or "")
    if d.startswith("00"):
        d = "+" + d[2:]
    if d.startswith("+"):
        digits = d[1:]
    elif d.startswith("971"):
        digits = d
    elif d.startswith("0") and len(d) in (9, 10):
        digits = "971" + d[1:]
    elif re.fullmatch(r"5\d{8}", d):
        digits = "971" + d
    else:
        digits = d
    if not digits.isdigit() or not 8 <= len(digits) <= 15:
        return None
    return "+" + digits


def short_codes(text: str) -> list[str]:
    """UAE short codes / sender IDs mentioned in text, e.g. 2828 (Aman SMS)."""
    return re.findall(r"\b\d{4,5}\b", text or "")


def normalize(indicator_type: str, raw: str) -> str:
    raw = (raw or "").strip()
    if indicator_type in ("url", "qr"):
        p = parse(raw)
        path = p.path.rstrip("/") or ""
        return f"{p.host.removeprefix('www.')}{path}" + (f"?{p.query}" if p.query else "")
    if indicator_type == "domain":
        return parse(raw).host.removeprefix("www.")
    if indicator_type == "phone":
        return normalize_phone(raw) or raw
    if indicator_type == "email":
        return raw.lower()
    return re.sub(r"\s+", " ", raw.lower())[:500]


def _next_id() -> str:
    n = db().execute("SELECT COUNT(*) FROM threats").fetchone()[0] + 1
    return f"RQ-{time.strftime('%Y')}-{n:05d}"


def _hist(entry: dict) -> dict:
    return {**entry, "ts": time.time()}


def upsert(indicator_type: str, raw: str, category: str, brand: str = "", risk: float = 0.0, confidence: float = 0.0,
           evidence: dict | None = None, emirate: str | None = None, source: str = "citizen", status: str = "under_review",
           actor: str = "system") -> tuple[dict, bool]:
    """Create or update the threat record for an indicator. Returns (threat, created)."""
    norm = normalize(indicator_type, raw)
    now = time.time()
    with LOCK:
        t = one(db().execute("SELECT * FROM threats WHERE indicator_type = ? AND normalized = ?", (indicator_type, norm)))
        if t:
            ev = json.loads(t["evidence"] or "{}")
            if evidence:
                ev.setdefault("observations", []).append({**evidence, "ts": now})
                ev["observations"] = ev["observations"][-50:]
            em = json.loads(t["emirates"] or "{}")
            if emirate:
                em[emirate] = em.get(emirate, 0) + 1
            hist = json.loads(t["history"] or "[]")
            hist.append(_hist({"event": "observed", "by": actor, "source": source}))
            db().execute("""UPDATE threats SET last_seen=?, report_count=report_count+1, risk=MAX(COALESCE(risk,0),?),
                         ai_confidence=MAX(COALESCE(ai_confidence,0),?), severity=?, brand=COALESCE(NULLIF(brand,''),?), evidence=?,
                         emirates=?, history=? WHERE id=?""",
                         (now, risk, confidence, severity(max(t["risk"] or 0, risk)), brand, json.dumps(ev), json.dumps(em), json.dumps(hist[-200:]), t["id"]))
            return get(t["id"]), False
        tid = _next_id()
        db().execute("""INSERT INTO threats (id, category, indicator_type, original, normalized, brand, first_seen, last_seen,
                     report_count, ai_confidence, risk, status, severity, evidence, history, emirates, source)
                     VALUES (?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?)""",
                     (tid, category, indicator_type, raw[:2000], norm, brand, now, now, confidence, risk, status,
                      severity(risk), json.dumps({"observations": [{**(evidence or {}), "ts": now}]}),
                      json.dumps([_hist({"event": "created", "by": actor, "source": source, "status": status})]),
                      json.dumps({emirate: 1} if emirate else {}), source))
        return get(tid), True


def severity(risk: float) -> str:
    return "critical" if risk >= 90 else "high" if risk >= 70 else "medium" if risk >= 50 else "low"


def get(tid: str) -> dict | None:
    t = one(db().execute("SELECT * FROM threats WHERE id = ?", (tid,)))
    if t:
        for k in ("evidence", "history", "emirates"):
            t[k] = json.loads(t[k] or ("[]" if k == "history" else "{}"))
        t["status_label"] = STATUS_LABELS.get(t["status"], t["status"])
        t["category_label"] = CATEGORIES.get(t["category"], t["category"])
        t["corroborations"] = db().execute("SELECT COUNT(*) FROM corroborations WHERE threat_id=?", (tid,)).fetchone()[0]
    return t


def find(indicator_type: str, raw: str) -> dict | None:
    t = one(db().execute("SELECT id FROM threats WHERE indicator_type=? AND normalized=?", (indicator_type, normalize(indicator_type, raw))))
    return get(t["id"]) if t else None


def set_status(tid: str, status: str, actor: str, note: str = "") -> dict:
    if status not in STATUSES:
        raise ValueError("unknown status")
    with LOCK:
        t = get(tid)
        if not t:
            raise KeyError(tid)
        t["history"].append(_hist({"event": "status", "from": t["status"], "to": status, "by": actor, "note": note[:500]}))
        db().execute("UPDATE threats SET status=?, reviewer=?, history=? WHERE id=?",
                     (status, actor if actor != "system" else t["reviewer"], json.dumps(t["history"][-200:]), tid))
    return get(tid)


def add_history(tid: str, entry: dict):
    with LOCK:
        t = get(tid)
        t["history"].append(_hist(entry))
        db().execute("UPDATE threats SET history=? WHERE id=?", (json.dumps(t["history"][-200:]), tid))


def search(q: str = "", status: str | None = None, category: str | None = None, limit: int = 200) -> list[dict]:
    sql, args = "SELECT id FROM threats WHERE 1=1", []
    if q:
        sql += " AND (normalized LIKE ? OR brand LIKE ? OR id LIKE ?)"
        args += [f"%{q}%"] * 3
    if status:
        sql += " AND status = ?"
        args.append(status)
    if category:
        sql += " AND category = ?"
        args.append(category)
    sql += " ORDER BY last_seen DESC LIMIT ?"
    args.append(min(limit, 1000))
    out = []
    for r in rows(db().execute(sql, args)):
        t = get(r["id"])
        t.pop("history", None)
        t["evidence"] = {"observations": len(t["evidence"].get("observations", []))}
        out.append(t)
    return out


def category_for(indicator_type: str, brand_sector: str | None, report_type: str | None) -> str:
    by_report = {"phone": "scam_phone", "sms": "sms", "whatsapp": "sms", "email": "email", "social": "fake_social",
                 "ad": "fraud_ad", "qr": "qr", "app": "fraud_app", "gov_bank": "impersonation"}
    if indicator_type == "phone":
        return "scam_phone"
    if indicator_type == "qr":
        return "qr"
    if report_type in ("ad", "social", "app"):
        return by_report[report_type]
    if indicator_type in ("url", "domain") and brand_sector:
        return SECTOR_CATEGORY.get(brand_sector, "phishing_website")
    if indicator_type in ("url", "domain"):
        return "phishing_website"
    return by_report.get(report_type or "", "other")
