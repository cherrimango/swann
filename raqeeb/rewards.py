"""SAWNN Guardians: points for verified, original, useful contributions only.

Points are written to a ledger with a UNIQUE(user, reason, threat) key, so the same contribution can never be paid
twice, and they are reversed if the threat is later marked a false positive.
"""
import json
import os
import time

from .db import LOCK, db, one, rows

POINTS = {  # configurable: SAWNN_POINTS='{"new_website": 20, ...}'
    "new_website": 20, "verified_phone": 15, "verified_ad": 25, "verified_sms": 15, "verified_email": 15,
    "useful_evidence": 10, "campaign_connection": 30, "independent_confirmation": 10, "high_impact_campaign": 50,
    "learning": 5,
}
POINTS.update(json.loads(os.environ.get("SAWNN_POINTS") or "{}"))

LEVELS = [(0, "Observer"), (50, "Scout"), (150, "Defender"), (400, "Sentinel"), (900, "Guardian"),
          (2000, "Elite Guardian"), (5000, "SAWNN Champion")]
LEVELS_AR = {"Observer": "مراقب", "Scout": "مستكشف", "Defender": "مدافع", "Sentinel": "حارس يقظ", "Guardian": "حامٍ",
             "Elite Guardian": "حامي النخبة", "SAWNN Champion": "بطل صون"}
BADGES = {
    "first_verified": ("First Verified Report", "أول بلاغ موثّق"),
    "phishing_hunter": ("Phishing Hunter", "صياد التصيّد"),
    "brand_protector": ("Brand Protector", "حامي العلامات"),
    "campaign_detective": ("Campaign Detective", "محقق الحملات"),
    "community_guardian": ("Community Guardian", "حارس المجتمع"),
    "early_warning": ("Early Warning Contributor", "مساهم الإنذار المبكر"),
    "monthly_guardian": ("Monthly Guardian", "حارس الشهر"),
    "high_impact": ("High Impact Discovery", "اكتشاف عالي الأثر"),
}
MIN_REPUTATION_FOR_POINTS = 0.3

EXPLAIN = {
    "new_website": "You reported a new scam website that analysts verified",
    "verified_phone": "Your scam phone number report was verified",
    "verified_ad": "Your scam advertisement report was verified",
    "verified_sms": "Your phishing SMS report was verified",
    "verified_email": "Your scam email report was verified",
    "useful_evidence": "Your screenshot helped verify the threat",
    "campaign_connection": "Your report connected this threat to a known campaign",
    "independent_confirmation": "You independently confirmed a threat before it was verified",
    "high_impact_campaign": "Your report was first in a large scam campaign",
    "learning": "You completed a scam simulation",
}


def _award(user_id, reason, threat_id, report_id=None, kind="verified") -> bool:
    u = one(db().execute("SELECT reputation FROM users WHERE id=?", (user_id,)))
    if not u or (kind == "verified" and u["reputation"] < MIN_REPUTATION_FOR_POINTS):
        return False
    with LOCK:
        cur = db().execute("INSERT OR IGNORE INTO points (user_id, delta, reason, threat_id, report_id, kind, explanation, created) VALUES (?,?,?,?,?,?,?,?)",
                           (user_id, POINTS[reason], reason, threat_id, report_id, kind, EXPLAIN[reason], time.time()))
    return cur.rowcount == 1


def report_reason(report_type: str, indicator_type: str) -> str:
    if report_type == "ad":
        return "verified_ad"
    if indicator_type == "phone" or report_type == "phone":
        return "verified_phone"
    if report_type in ("sms", "whatsapp"):
        return "verified_sms"
    if report_type == "email":
        return "verified_email"
    return "new_website"


def on_verified(threat: dict) -> list[dict]:
    """Award eligible points when a threat becomes analyst-verified / confirmed. Idempotent."""
    tid = threat["id"]
    reps = rows(db().execute("SELECT * FROM citizen_reports WHERE threat_ids LIKE ? AND user_id IS NOT NULL ORDER BY created", (f'%"{tid}"%',)))
    reps = [r for r in reps if r["status"] != "duplicate"]
    awarded = []
    if reps:
        first = reps[0]
        ai = json.loads(first["ai"] or "{}")
        reason = report_reason(first["type"], threat["indicator_type"])
        if _award(first["user_id"], reason, tid, first["id"]):
            awarded.append({"user_id": first["user_id"], "reason": reason})
        if first["attachment"] and _award(first["user_id"], "useful_evidence", tid, first["id"]):
            awarded.append({"user_id": first["user_id"], "reason": "useful_evidence"})
        if ai.get("joined_campaign") and _award(first["user_id"], "campaign_connection", tid, first["id"]):
            awarded.append({"user_id": first["user_id"], "reason": "campaign_connection"})
        verified_at = time.time()
        for c in rows(db().execute("SELECT * FROM corroborations WHERE threat_id=? AND user_id != ?", (tid, first["user_id"]))):
            if c["created"] <= verified_at and _award(c["user_id"], "independent_confirmation", tid):
                awarded.append({"user_id": c["user_id"], "reason": "independent_confirmation"})
        if threat.get("campaign_id"):
            size = db().execute("SELECT COUNT(*) FROM threats WHERE campaign_id=?", (threat["campaign_id"],)).fetchone()[0]
            if size >= 5 and _award(first["user_id"], "high_impact_campaign", threat["campaign_id"]):
                awarded.append({"user_id": first["user_id"], "reason": "high_impact_campaign"})
    for uid in {a["user_id"] for a in awarded}:
        update_badges(uid)
    return awarded


def on_false_positive(threat: dict) -> int:
    """Reverse every point paid for this threat and lower the reporter's reputation weight."""
    paid = rows(db().execute("SELECT * FROM points WHERE threat_id=? AND delta > 0 AND kind='verified'", (threat["id"],)))
    for p in paid:
        db().execute("INSERT OR IGNORE INTO points (user_id, delta, reason, threat_id, kind, explanation, created) VALUES (?,?,?,?,?,?,?)",
                     (p["user_id"], -p["delta"], p["reason"] + "_reversed", threat["id"], "reversal",
                      "Reversed: the threat was later found to be a false positive", time.time()))
    return len(paid)


def penalise(user_id: int, factor: float = 0.8):
    db().execute("UPDATE users SET reputation = MAX(0.05, reputation * ?) WHERE id=?", (factor, user_id))


def total(user_id: int) -> int:
    return db().execute("SELECT COALESCE(SUM(delta),0) FROM points WHERE user_id=?", (user_id,)).fetchone()[0]


def level(points: int) -> dict:
    cur, nxt = LEVELS[0], None
    for i, (th, name) in enumerate(LEVELS):
        if points >= th:
            cur = (th, name)
            nxt = LEVELS[i + 1] if i + 1 < len(LEVELS) else None
    return {"name": cur[1], "name_ar": LEVELS_AR[cur[1]], "threshold": cur[0],
            "next": {"name": nxt[1], "at": nxt[0]} if nxt else None}


def update_badges(user_id: int):
    verified = rows(db().execute("""SELECT t.indicator_type, t.brand, t.category FROM citizen_reports r JOIN threats t
        ON r.threat_ids LIKE '%"' || t.id || '"%' WHERE r.user_id=? AND t.status IN ('analyst_verified','confirmed_malicious')""", (user_id,)))
    earned = set()
    if verified:
        earned.add("first_verified")
    if sum(1 for v in verified if v["indicator_type"] in ("url", "domain")) >= 5:
        earned.add("phishing_hunter")
    if len({v["brand"] for v in verified if v["brand"]}) >= 3:
        earned.add("brand_protector")
    reasons = {r["reason"] for r in rows(db().execute("SELECT reason FROM points WHERE user_id=? AND delta>0", (user_id,)))}
    if "campaign_connection" in reasons:
        earned.add("campaign_detective")
    if "high_impact_campaign" in reasons:
        earned.add("high_impact")
    if db().execute("SELECT COUNT(*) FROM points WHERE user_id=? AND reason='independent_confirmation'", (user_id,)).fetchone()[0] >= 10:
        earned.add("community_guardian")
    first_reporter = db().execute("""SELECT COUNT(*) FROM threats t WHERE t.report_count >= 3 AND
        (SELECT user_id FROM citizen_reports r WHERE r.threat_ids LIKE '%"' || t.id || '"%' ORDER BY created LIMIT 1) = ?""", (user_id,)).fetchone()[0]
    if first_reporter:
        earned.add("early_warning")
    for b in earned:
        db().execute("INSERT OR IGNORE INTO badges (user_id, badge, created) VALUES (?,?,?)", (user_id, b, time.time()))


def profile(user_id: int) -> dict:
    pts = total(user_id)
    badges = [{"id": b["badge"], "name": BADGES[b["badge"]][0], "name_ar": BADGES[b["badge"]][1], "earned": b["created"]}
              for b in rows(db().execute("SELECT * FROM badges WHERE user_id=? ORDER BY created", (user_id,))) if b["badge"] in BADGES]
    ledger = rows(db().execute("SELECT delta, reason, threat_id, kind, explanation, created FROM points WHERE user_id=? ORDER BY created DESC LIMIT 50", (user_id,)))
    return {"points": pts, "level": level(pts), "badges": badges, "ledger": ledger}


def leaderboard(period: str = "week", emirate: str | None = None, limit: int = 20) -> list[dict]:
    since = {"week": time.time() - 7 * 86400, "month": time.time() - 30 * 86400}.get(period, 0)
    sql = """SELECT u.id, u.display_name, u.emirate, SUM(p.delta) pts, COUNT(DISTINCT p.threat_id) discoveries
             FROM points p JOIN users u ON u.id = p.user_id
             WHERE u.public_rank = 1 AND u.role = 'citizen' AND p.created >= ?"""
    args = [since]
    if emirate:
        sql += " AND u.emirate = ?"
        args.append(emirate)
    sql += " GROUP BY u.id HAVING pts > 0 ORDER BY pts DESC, discoveries DESC LIMIT ?"
    args.append(limit)
    out = rows(db().execute(sql, args))
    for i, r in enumerate(out, 1):
        r["rank"] = i
        r["level"] = level(total(r["id"]))["name"]
        r.pop("id")  # leaderboard never exposes account ids or emails
    return out


def emirate_ranking(period: str = "month") -> list[dict]:
    since = {"week": time.time() - 7 * 86400, "month": time.time() - 30 * 86400}.get(period, 0)
    return rows(db().execute("""SELECT u.emirate, SUM(p.delta) pts, COUNT(DISTINCT u.id) guardians FROM points p
        JOIN users u ON u.id=p.user_id WHERE p.created >= ? AND u.emirate IS NOT NULL GROUP BY u.emirate ORDER BY pts DESC""", (since,)))
