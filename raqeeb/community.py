"""Community Intelligence: citizen reports, AI-assisted analysis, corroboration, verification workflow,
personal blocklists, family groups and notifications."""
import json
import secrets
import time

from . import agents, intel, rewards
from .db import LOCK, db, one, rows
from .intel import STATUS_LABELS, VERIFIED

REPORT_TYPES = {
    "website": "Suspicious website or link", "phone": "Suspicious phone number", "sms": "Fraudulent SMS",
    "whatsapp": "Suspicious WhatsApp message", "email": "Suspicious email", "social": "Fraudulent social media account",
    "ad": "Scam advertisement", "qr": "Suspicious QR code", "app": "Fraudulent mobile app",
    "gov_bank": "Fake government or banking communication", "other": "Other suspicious activity",
}
CORROBORATION_THRESHOLD = 3.0  # weighted, distinct citizens
IMPACT_KEYS = ["received", "clicked", "shared_details", "paid", "lost_money"]


def _ref() -> str:
    return "R-" + secrets.token_hex(3).upper()


def notify(title: str, body: str, kind: str, user_id: int | None = None, audience: str = "user", data: dict | None = None):
    db().execute("INSERT INTO notifications (user_id, audience, kind, title, body, data, created) VALUES (?,?,?,?,?,?,?)",
                 (user_id, audience, kind, title[:200], body[:600], json.dumps(data or {}), time.time()))


def submit(user: dict | None, rtype: str, text: str, emirate: str | None, attachment: dict | None = None,
           impact: dict | None = None, ip_hash: str = "", ocr_text: str = "") -> dict:
    """Run the full AI-assisted pipeline on a citizen report and return what the citizen should see."""
    text = (text or "")[:4000]
    analysed = (text + "\n" + ocr_text).strip()
    rtype = agents.detect_type(analysed, rtype, bool(attachment))
    if rtype not in REPORT_TYPES:
        rtype = "other"
    uid = user["id"] if user else None
    ref = _ref()
    now = time.time()
    cur = db().execute("""INSERT INTO citizen_reports (ref, user_id, type, raw_text, attachment, emirate, impact, status, ip_hash, created, updated)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                       (ref, uid, rtype, text, json.dumps(attachment) if attachment else None, emirate,
                        json.dumps({k: bool((impact or {}).get(k)) for k in IMPACT_KEYS}), "analysing", ip_hash, now, now))
    rid = cur.lastrowid

    ex = agents.extract(analysed)
    if rtype == "qr" and not ex["urls"] and text.strip():
        ex["urls"] = [text.strip()]
    findings = []
    url_results, f = agents.phishing_agent(ex["urls"])
    findings += f
    msg, mf = (None, None)
    if rtype in ("sms", "whatsapp", "email", "gov_bank", "social", "other") and text.strip():
        msg, mf = agents.message_agent(analysed)
        findings.append(mf)
    ad = None
    if rtype == "ad":
        ad, af = agents.ad_agent(analysed, url_results)
        findings.append(af)
    phone_results = []
    for p in ex["phones"]:
        pr, pf = agents.phone_agent(p)
        phone_results.append(pr)
        findings.append(pf)

    normalized = [intel.normalize("url", u) for u in ex["urls"]] + ex["phones"] + [e.lower() for e in ex["emails"]]
    comm = agents.community_agent(uid, normalized)

    risks = [r["risk_score"] for r in url_results] + [p["risk"] for p in phone_results]
    if msg:
        risks.append(msg["risk_score"])
    if ad:
        risks.append(ad["risk"])
    risk = max(risks, default=0.0)

    threat_ids, joined_existing, created_new = [], False, False
    with LOCK:
        for r in url_results:
            b = r.get("impersonated_brand") or {}
            itype = "qr" if rtype == "qr" else "url"
            cat = intel.category_for(itype, agents.brand_sector(b.get("name")), rtype)
            t, new = intel.upsert(itype, r["url"], cat, b.get("name", ""), r["risk_score"], r["risk_score"] / 100,
                                  {"report": ref, "verdict": r["verdict"], "reasons": [x["en"] for x in r["reasons"][:4]]},
                                  emirate, source="citizen report", status="under_review", actor=f"citizen:{uid or 'anonymous'}")
            threat_ids.append(t["id"])
            joined_existing |= not new
            created_new |= new
        for p in phone_results:
            t, new = intel.upsert("phone", p["number"], "scam_phone", "", p["risk"], p["risk"] / 100,
                                  {"report": ref, "signals": p["signals"]}, emirate, source="citizen report", actor=f"citizen:{uid or 'anonymous'}")
            threat_ids.append(t["id"])
            joined_existing |= not new
        if not threat_ids and msg and msg["risk_score"] >= 35:  # a scam message with no link or number
            cat = intel.category_for("text", None, rtype)
            t, new = intel.upsert("text", analysed[:500], cat, (msg["brands_named"] or [""])[0], msg["risk_score"],
                                  msg["risk_score"] / 100, {"report": ref}, emirate, source="citizen report")
            threat_ids.append(t["id"])

    status = "duplicate" if comm["duplicate_of"] else "under_review"
    before = {t["id"]: t["campaign_id"] for t in rows(db().execute("SELECT id, campaign_id FROM threats"))}
    ai = {
        "type_detected": rtype, "indicators": ex, "risk": round(risk, 1), "severity": intel.severity(risk),
        "links": [{"url": r["url"], "risk": r["risk_score"], "verdict": r["verdict"],
                   "brand": (r.get("impersonated_brand") or {}).get("name"), "reasons_en": [x["en"] for x in r["reasons"][:4]],
                   "reasons_ar": [x["ar"] for x in r["reasons"][:4]]} for r in url_results],
        "phones": phone_results, "message": {k: msg[k] for k in ("verdict", "risk_score", "script_signals", "brands_named", "advice_en", "advice_ar")} if msg else None,
        "advertisement": ad, "community": comm, "findings": [agents.as_dict(f) for f in findings],
        "joined_existing_threat": joined_existing, "explanation_en": _explain(url_results, msg, phone_results, ad, "en"),
        "explanation_ar": _explain(url_results, msg, phone_results, ad, "ar"),
    }
    db().execute("UPDATE citizen_reports SET indicators=?, status=?, threat_ids=?, ai=?, duplicate_of=?, updated=? WHERE id=?",
                 (json.dumps(normalized), status, json.dumps(threat_ids), json.dumps(ai, default=str), comm["duplicate_of"], time.time(), rid))
    for f in findings:
        f.save()

    graph = agents.correlate()
    after = {t["id"]: t["campaign_id"] for t in rows(db().execute("SELECT id, campaign_id FROM threats"))}
    # Credit only for linking to threats this report did not itself contain (a real connection to a known campaign).
    joined_campaign = any(after.get(t) and any(v == after[t] and k not in threat_ids for k, v in after.items()) for t in threat_ids)
    if joined_campaign:
        ai["joined_campaign"] = True
        db().execute("UPDATE citizen_reports SET ai=? WHERE id=?", (json.dumps(ai, default=str), rid))

    if user and status != "duplicate":
        for tid in threat_ids:
            corroborate(user, tid, rid, auto=True)
    return citizen_view(get_report(rid)) | {"campaigns": len(graph["campaigns"])}


def _explain(urls, msg, phones, ad, lang) -> str:
    parts = []
    for r in urls:
        if r["label"] or r["verdict"] == "suspicious":
            b = r.get("impersonated_brand")
            if b:
                parts.append(f"The link pretends to be {b['name']}." if lang == "en" else f"الرابط ينتحل صفة {b['name_ar']}.")
            if r["reasons"]:
                parts.append(r["reasons"][0][lang].rstrip(".") + ".")
    if msg and msg["script_signals"]:
        parts.append(("Scam signs in the message: " if lang == "en" else "علامات احتيال في الرسالة: ") +
                     "، ".join(s[lang] for s in msg["script_signals"][:3]) if lang == "ar" else
                     "Scam signs in the message: " + ", ".join(s[lang].lower() for s in msg["script_signals"][:3]) + ".")
    for p in phones:
        if p["signals"]:
            parts.append(p["signals"][0] if lang == "en" else "تم تحليل الرقم ومقارنته بالبلاغات السابقة.")
    if ad and ad["signals"]:
        parts.append(("Advertisement signs: " + ", ".join(s["en"].lower() for s in ad["signals"])) if lang == "en"
                     else "علامات إعلان احتيالي: عرض مبالغ فيه أو طريقة دفع غير معتادة.")
    if not parts:
        return "No strong scam signals yet. Analysts will review it." if lang == "en" else "لا توجد علامات احتيال قوية حتى الآن، وسيراجعه المحللون."
    return " ".join(p if p.endswith((".", "۔")) else p + "." for p in (x.strip() for x in parts) if p)


def corroborate(user: dict, tid: str, report_id: int | None = None, auto: bool = False) -> dict:
    """'I saw this too.' One per citizen per threat, weighted by the citizen's reputation."""
    t = intel.get(tid)
    if not t:
        raise KeyError(tid)
    with LOCK:
        cur = db().execute("INSERT OR IGNORE INTO corroborations (threat_id, user_id, report_id, weight, created) VALUES (?,?,?,?,?)",
                           (tid, user["id"], report_id, user.get("reputation", 1.0), time.time()))
        if cur.rowcount == 1 and not auto:
            db().execute("UPDATE threats SET report_count = report_count + 1, last_seen=? WHERE id=?", (time.time(), tid))
    weight = db().execute("SELECT COALESCE(SUM(weight),0), COUNT(*) FROM corroborations WHERE threat_id=?", (tid,)).fetchone()
    t = intel.get(tid)
    # Corroboration raises priority but never confirms a threat by itself: it also needs independent AI evidence.
    if t["status"] == "under_review" and weight[0] >= CORROBORATION_THRESHOLD and (t["risk"] or 0) >= 50:
        t = intel.set_status(tid, "community_corroborated", "system", f"{weight[1]} citizens, weight {weight[0]:.1f}")
        _sync_reports(t)
    return {"threat_id": tid, "corroborations": weight[1], "weight": round(weight[0], 2), "status": t["status"]}


def review(tid: str, new_status: str, actor: dict, note: str = "") -> dict:
    """Analyst decision. Pays points on verification, reverses them on false positives, keeps reports in sync."""
    t = intel.set_status(tid, new_status, actor["email"], note)
    if new_status in VERIFIED:
        rewards.on_verified(t)
    if new_status == "false_positive":
        rewards.on_false_positive(t)
        for r in reports_for(tid):
            if r["user_id"]:
                rewards.penalise(r["user_id"], 0.9)
    if new_status == "rejected":
        for r in reports_for(tid):
            if r["user_id"]:
                rewards.penalise(r["user_id"], 0.85)
    if new_status in ("false_positive", "rejected") and t["block_status"] == "global":
        from . import protection
        protection.release(tid, actor["email"], f"marked {new_status}")
        t = intel.get(tid)
    _sync_reports(t)
    return t


REPORT_STATUS_FROM_THREAT = {
    "community_corroborated": "community_corroborated", "analyst_verified": "analyst_verified",
    "confirmed_malicious": "confirmed_malicious", "rejected": "rejected", "false_positive": "false_positive",
    "resolved": "resolved", "under_review": "under_review",
}


def reports_for(tid: str) -> list[dict]:
    return rows(db().execute("SELECT * FROM citizen_reports WHERE threat_ids LIKE ?", (f'%"{tid}"%',)))


def _sync_reports(t: dict):
    target = REPORT_STATUS_FROM_THREAT.get(t["status"])
    if not target:
        return
    for r in reports_for(t["id"]):
        if r["status"] == "duplicate" or r["status"] == target:
            continue
        db().execute("UPDATE citizen_reports SET status=?, updated=? WHERE id=?", (target, time.time(), r["id"]))
        if r["user_id"] and target in ("analyst_verified", "confirmed_malicious", "false_positive", "rejected"):
            notify(f"Your report {r['ref']}: {STATUS_LABELS[target]}", "Thank you for helping protect the UAE community.",
                   "report_status", user_id=r["user_id"], data={"ref": r["ref"], "status": target})


def get_report(rid) -> dict | None:
    r = one(db().execute("SELECT * FROM citizen_reports WHERE id=? OR ref=?", (rid, rid)))
    if r:
        for k in ("indicators", "threat_ids", "ai", "impact", "attachment"):
            r[k] = json.loads(r[k]) if r[k] else None
        r["status_label"] = STATUS_LABELS.get(r["status"], r["status"])
    return r


def citizen_view(r: dict) -> dict:
    """What a citizen may see about their own report: progress and explanation, no investigation detail."""
    ai = r["ai"] or {}
    return {"ref": r["ref"], "type": r["type"], "type_label": REPORT_TYPES.get(r["type"], r["type"]), "status": r["status"],
            "status_label": r["status_label"], "created": r["created"], "updated": r["updated"],
            "risk": ai.get("risk"), "severity": ai.get("severity"), "explanation_en": ai.get("explanation_en"),
            "explanation_ar": ai.get("explanation_ar"), "links": [{k: l[k] for k in ("url", "risk", "verdict", "brand")} for l in ai.get("links", [])],
            "duplicate_of": r["duplicate_of"], "threat_refs": r["threat_ids"] or []}


def my_reports(uid: int) -> list[dict]:
    return [citizen_view(get_report(r["id"])) for r in rows(db().execute("SELECT id FROM citizen_reports WHERE user_id=? ORDER BY created DESC LIMIT 100", (uid,)))]


def queue(status: str | None = None, limit: int = 200) -> list[dict]:
    sql, args = "SELECT id FROM citizen_reports", []
    if status:
        sql += " WHERE status=?"
        args.append(status)
    sql += " ORDER BY created DESC LIMIT ?"
    args.append(limit)
    out = []
    for r in rows(db().execute(sql, args)):
        full = get_report(r["id"])
        full["reporter"] = None
        if full["user_id"]:
            u = one(db().execute("SELECT display_name, reputation FROM users WHERE id=?", (full["user_id"],)))
            full["reporter"] = u
        out.append(full)
    return out


# ---------- personal protection ----------
def block_for_me(user: dict, value: str) -> dict:
    from .intel import normalize_phone
    kind = "phone" if normalize_phone(value) and not any(c.isalpha() for c in value) else "url"
    norm = normalize_phone(value) if kind == "phone" else intel.normalize("domain", value)
    db().execute("INSERT OR IGNORE INTO personal_blocks (user_id, value, kind, created) VALUES (?,?,?,?)", (user["id"], norm, kind, time.time()))
    return {"value": norm, "kind": kind}


def my_blocks(uid: int) -> list[dict]:
    return rows(db().execute("SELECT value, kind, created FROM personal_blocks WHERE user_id=? ORDER BY created DESC", (uid,)))


def unblock_for_me(uid: int, value: str):
    db().execute("DELETE FROM personal_blocks WHERE user_id=? AND value=?", (uid, value))


def personally_blocked(uid: int | None, host_or_phone: str) -> bool:
    if not uid:
        return False
    h = host_or_phone.lower().removeprefix("www.")
    parts = h.split(".")
    cands = [".".join(parts[i:]) for i in range(len(parts))] + [h]
    q = "SELECT 1 FROM personal_blocks WHERE user_id=? AND value IN (%s)" % ",".join("?" * len(cands))
    return db().execute(q, [uid, *cands]).fetchone() is not None


# ---------- family protection (opt-in sharing of alerts, never monitoring) ----------
def create_family(user: dict, name: str) -> dict:
    code = secrets.token_hex(3).upper()
    cur = db().execute("INSERT INTO families (name, code, owner, created) VALUES (?,?,?,?)", ((name or "My family")[:40], code, user["id"], time.time()))
    db().execute("INSERT INTO family_members (family_id, user_id) VALUES (?,?)", (cur.lastrowid, user["id"]))
    return {"id": cur.lastrowid, "name": name, "code": code}


def join_family(user: dict, code: str) -> dict:
    f = one(db().execute("SELECT * FROM families WHERE code=?", ((code or "").upper().strip(),)))
    if not f:
        raise KeyError("No family group with that code")
    db().execute("INSERT OR IGNORE INTO family_members (family_id, user_id) VALUES (?,?)", (f["id"], user["id"]))
    return {"id": f["id"], "name": f["name"]}


def my_family(uid: int) -> dict | None:
    f = one(db().execute("SELECT f.* FROM families f JOIN family_members m ON m.family_id=f.id WHERE m.user_id=? LIMIT 1", (uid,)))
    if not f:
        return None
    members = rows(db().execute("SELECT u.display_name FROM family_members m JOIN users u ON u.id=m.user_id WHERE m.family_id=?", (f["id"],)))
    return {"name": f["name"], "code": f["code"] if f["owner"] == uid else None, "members": [m["display_name"] for m in members]}


def share_with_family(user: dict, title: str, body: str) -> int:
    f = one(db().execute("SELECT family_id FROM family_members WHERE user_id=? LIMIT 1", (user["id"],)))
    if not f:
        raise KeyError("Join or create a family group first")
    members = rows(db().execute("SELECT user_id FROM family_members WHERE family_id=? AND user_id != ?", (f["family_id"], user["id"])))
    for m in members:
        notify(f"{user['display_name']} shared a scam warning: {title}"[:200], body, "family_alert", user_id=m["user_id"])
    return len(members)


def my_notifications(uid: int, limit=50) -> list[dict]:
    return rows(db().execute("""SELECT id, kind, title, body, data, created FROM notifications
        WHERE user_id=? OR audience='citizens' ORDER BY created DESC LIMIT ?""", (uid, limit)))
