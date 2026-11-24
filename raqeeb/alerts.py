"""Command-to-citizen alerts: draft -> review -> translation -> approval -> publish -> delivery and engagement tracking.

Rules enforced here (not just in the UI):
- An alert needs English AND Arabic text before it can be sent for review.
- The reviewer and the approver must be different people from the author; approval needs the approve_threat permission.
- AI may draft, never publish: AI drafts are marked ai_drafted and still go through review and human approval.
- Delivery is recorded per channel. In-app delivery is real (written to each recipient's notifications). Push, email and SMS
  are only attempted when a provider key is configured; otherwise the channel is recorded as "not configured" and nothing
  is claimed as delivered.
- Every transition is written to the audit log with the actor, time, status and version.
"""
import json
import os
import secrets
import time

from . import auth
from .db import db, one, rows

CATEGORIES = {
    "phishing_link": ("Phishing links", "روابط تصيد"), "fake_government": ("Fake government services", "خدمات حكومية مزيفة"),
    "bank_otp": ("Bank and OTP scams", "احتيال البنوك ورموز التحقق"), "delivery": ("Fake delivery and customs fees", "رسوم توصيل وجمارك مزيفة"),
    "job": ("Fake job offers", "عروض عمل مزيفة"), "investment": ("Investment and crypto scams", "احتيال الاستثمار والعملات الرقمية"),
    "shopping": ("Fake shops and ads", "متاجر وإعلانات مزيفة"), "phone": ("Scam calls", "مكالمات احتيالية"),
    "seasonal": ("Seasonal scams", "احتيال موسمي"), "qr": ("QR code scams", "احتيال رموز QR"), "other": ("Other", "أخرى"),
}
SEVERITIES = ("low", "medium", "high", "critical")
CHANNELS = {"in_app": None, "push": "MIRA_PUSH_PROVIDER_KEY", "email": "MIRA_EMAIL_PROVIDER_KEY", "sms": "MIRA_SMS_PROVIDER_KEY"}
FIELDS = ("title", "description", "warning_signs", "what_to_do", "never_share", "official_resources")
STATUSES = ("draft", "in_review", "reviewed", "approved", "published", "withdrawn", "rejected")


class AlertError(ValueError):
    pass


def _audit(action, alert_id, actor, extra=None):
    db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,?,?)",
                 (action, json.dumps({"alert_id": alert_id, **(extra or {})}), time.time(), actor))


def _load(aid):
    a = one(db().execute("SELECT * FROM citizen_alerts WHERE id = ?", (aid,)))
    if not a:
        raise AlertError("Alert not found")
    for k in ("content", "audience", "channels", "brands", "threat_ids"):
        a[k] = json.loads(a[k]) if a.get(k) else ([] if k in ("channels", "brands", "threat_ids") else {})
    return a


def _clean_content(c: dict) -> dict:
    out = {}
    for lang in ("en", "ar"):
        src = (c or {}).get(lang) or {}
        out[lang] = {}
        for f in FIELDS:
            v = src.get(f, "")
            if isinstance(v, list):
                v = [str(x)[:300] for x in v if str(x).strip()][:10]
            else:
                v = str(v or "")[:2000]
            out[lang][f] = v
    return out


def _complete(content, lang):
    c = content.get(lang) or {}
    return bool(str(c.get("title", "")).strip()) and bool(str(c.get("description", "")).strip())


def _audience(a):
    a = a or {}
    kind = a.get("kind", "all")
    if kind not in ("all", "subscribers", "emirate"):
        raise AlertError("Audience must be all, subscribers or emirate")
    em = [e for e in a.get("emirates", []) if e in auth.EMIRATES]
    if kind == "emirate" and not em:
        raise AlertError("Choose at least one emirate")
    return {"kind": kind, "emirates": em}


def create(data: dict, actor: dict, ai_drafted=False, demo=False) -> dict:
    cat = data.get("category", "other")
    sev = data.get("severity", "medium")
    if cat not in CATEGORIES or sev not in SEVERITIES:
        raise AlertError("Unknown category or severity")
    chans = [c for c in data.get("channels", ["in_app"]) if c in CHANNELS] or ["in_app"]
    aid = "ALR-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()
    content = _clean_content(data.get("content", {}))
    exp = data.get("expires_in_days")
    expires = time.time() + 86400 * max(1, min(int(exp), 365)) if exp else None
    db().execute("""INSERT INTO citizen_alerts (id, status, severity, category, audience, channels, content, brands, threat_ids, expires,
        ai_drafted, demo, created_by, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (aid, "draft", sev, cat, json.dumps(_audience(data.get("audience"))), json.dumps(chans), json.dumps(content),
                  json.dumps([str(b)[:60] for b in data.get("brands", [])][:10]), json.dumps(data.get("threat_ids", [])[:20]),
                  expires, int(ai_drafted), int(demo), actor["email"], time.time()))
    db().execute("INSERT INTO citizen_alert_versions VALUES (?,?,?,?,?)", (aid, 1, json.dumps(content), actor["email"], time.time()))
    _audit("alert_create", aid, actor["email"], {"ai_drafted": ai_drafted, "version": 1})
    db().commit()
    return get(aid)


def update(aid, data: dict, actor: dict) -> dict:
    a = _load(aid)
    if a["status"] not in ("draft", "reviewed", "rejected"):
        raise AlertError("Only drafts can be edited; withdraw a published alert and create a new one")
    content = _clean_content(data.get("content", a["content"]))
    v = a["version"] + 1
    sets = {"content": json.dumps(content), "version": v, "status": "draft", "reviewed_by": None, "reviewed": None}
    if "audience" in data:
        sets["audience"] = json.dumps(_audience(data["audience"]))
    if "channels" in data:
        sets["channels"] = json.dumps([c for c in data["channels"] if c in CHANNELS] or ["in_app"])
    for k in ("severity", "category"):
        if k in data:
            if (k == "severity" and data[k] not in SEVERITIES) or (k == "category" and data[k] not in CATEGORIES):
                raise AlertError(f"Unknown {k}")
            sets[k] = data[k]
    db().execute(f"UPDATE citizen_alerts SET {', '.join(k + ' = ?' for k in sets)} WHERE id = ?", (*sets.values(), aid))
    db().execute("INSERT INTO citizen_alert_versions VALUES (?,?,?,?,?)", (aid, v, json.dumps(content), actor["email"], time.time()))
    _audit("alert_edit", aid, actor["email"], {"version": v})
    db().commit()
    return get(aid)


def submit(aid, actor):
    a = _load(aid)
    if a["status"] != "draft":
        raise AlertError("Only a draft can be sent for review")
    missing = [l for l in ("en", "ar") if not _complete(a["content"], l)]
    if missing:
        raise AlertError("Add a title and description in " + " and ".join({"en": "English", "ar": "Arabic"}[m] for m in missing) + " first")
    db().execute("UPDATE citizen_alerts SET status = 'in_review' WHERE id = ?", (aid,))
    _audit("alert_submit", aid, actor["email"], {"version": a["version"]})
    db().commit()
    return get(aid)


def review(aid, actor, ok: bool, note: str = ""):
    a = _load(aid)
    if a["status"] != "in_review":
        raise AlertError("This alert is not waiting for review")
    if actor["email"] == a["created_by"]:
        raise AlertError("The author can’t review their own alert")
    st = "reviewed" if ok else "rejected"
    db().execute("UPDATE citizen_alerts SET status=?, reviewed_by=?, reviewed=?, review_note=? WHERE id=?",
                 (st, actor["email"], time.time(), note[:500], aid))
    _audit("alert_review", aid, actor["email"], {"result": st, "version": a["version"]})
    db().commit()
    return get(aid)


def approve(aid, actor):
    a = _load(aid)
    if not auth.can(actor["role"], "approve_threat"):
        raise PermissionError("Only an authorised administrator can approve a citizen alert")
    if a["status"] != "reviewed":
        raise AlertError("An alert must be reviewed before approval")
    if actor["email"] == a["created_by"]:
        raise AlertError("The author can’t approve their own alert")
    db().execute("UPDATE citizen_alerts SET status='approved', approved_by=?, approved=? WHERE id=?", (actor["email"], time.time(), aid))
    _audit("alert_approve", aid, actor["email"], {"version": a["version"]})
    db().commit()
    return get(aid)


def _recipients(a) -> list[int]:
    aud = a["audience"]
    q = "SELECT id FROM users WHERE role = 'citizen' AND disabled = 0"
    args: list = []
    if aud["kind"] == "emirate":
        q += f" AND emirate IN ({','.join('?' * len(aud['emirates']))})"
        args += aud["emirates"]
    ids = [r["id"] for r in rows(db().execute(q, args))]
    if aud["kind"] == "subscribers":
        subs = {r["user_id"] for r in rows(db().execute("SELECT user_id FROM alert_subscriptions WHERE category = ?", (a["category"],)))}
        ids = [i for i in ids if i in subs]
    return ids


def publish(aid, actor):
    a = _load(aid)
    if not auth.can(actor["role"], "approve_threat"):
        raise PermissionError("Only an authorised administrator can publish a citizen alert")
    if a["status"] != "approved":
        raise AlertError("Only an approved alert can be published")
    now = time.time()
    ids = _recipients(a)
    deliveries = []
    for ch in a["channels"]:
        if ch == "in_app":
            for uid in ids:
                db().execute("INSERT INTO notifications (user_id, audience, kind, title, body, data, created) VALUES (?,?,?,?,?,?,?)",
                             (uid, "user", "citizen_alert", a["content"]["en"]["title"][:200], a["content"]["en"]["description"][:600],
                              json.dumps({"alert_id": aid}), now))
            st, n, detail = "delivered_in_app", len(ids), "written to each recipient's MIRA Protect inbox; live sessions notified"
        elif os.environ.get(CHANNELS[ch]):
            # A provider adapter would be called here. No adapter ships with MIRA yet, so nothing is claimed as sent.
            st, n, detail = "provider_configured_adapter_missing", 0, f"{CHANNELS[ch]} is set but no {ch} adapter is implemented yet"
        else:
            st, n, detail = "not_configured", 0, f"set {CHANNELS[ch]} and add a provider adapter to send by {ch}"
        db().execute("INSERT INTO alert_deliveries (alert_id, channel, status, recipients, detail, created) VALUES (?,?,?,?,?,?)",
                     (aid, ch, st, n, detail, now))
        deliveries.append({"channel": ch, "status": st, "recipients": n, "detail": detail})
    db().execute("UPDATE citizen_alerts SET status='published', published_by=?, published=? WHERE id=?", (actor["email"], now, aid))
    _audit("alert_publish", aid, actor["email"], {"version": a["version"], "recipients": len(ids), "channels": a["channels"]})
    db().commit()
    out = get(aid)
    out["deliveries_now"] = deliveries
    return out


def withdraw(aid, actor):
    a = _load(aid)
    if a["status"] != "published":
        raise AlertError("Only a published alert can be withdrawn")
    db().execute("UPDATE citizen_alerts SET status='withdrawn', withdrawn_by=?, withdrawn=? WHERE id=?", (actor["email"], time.time(), aid))
    _audit("alert_withdraw", aid, actor["email"], {"version": a["version"]})
    db().commit()
    return get(aid)


def get(aid) -> dict:
    a = _load(aid)
    a["deliveries"] = rows(db().execute("SELECT channel, status, recipients, detail, created FROM alert_deliveries WHERE alert_id=? ORDER BY id", (aid,)))
    eng = rows(db().execute("SELECT action, COUNT(*) n FROM alert_engagement WHERE alert_id=? GROUP BY action", (aid,)))
    a["engagement"] = {r["action"]: r["n"] for r in eng}
    a["versions"] = rows(db().execute("SELECT version, edited_by, edited FROM citizen_alert_versions WHERE alert_id=? ORDER BY version", (aid,)))
    a["category_label"] = CATEGORIES.get(a["category"], (a["category"],))[0]
    return a


def list_all(status=None) -> list[dict]:
    q, args = "SELECT id FROM citizen_alerts", []
    if status:
        q += " WHERE status = ?"
        args.append(status)
    return [get(r["id"]) for r in rows(db().execute(q + " ORDER BY created DESC LIMIT 200", args))]


def for_citizen(user: dict | None) -> list[dict]:
    """Published, unexpired alerts this person is in the audience for (anonymous visitors see 'all' alerts only)."""
    now = time.time()
    out = []
    for r in rows(db().execute("SELECT id FROM citizen_alerts WHERE status='published' AND (expires IS NULL OR expires > ?) ORDER BY published DESC LIMIT 50", (now,))):
        a = get(r["id"])
        aud = a["audience"]
        if aud["kind"] == "emirate" and not (user and user.get("emirate") in aud["emirates"]):
            continue
        if aud["kind"] == "subscribers" and not (user and one(db().execute(
                "SELECT 1 x FROM alert_subscriptions WHERE user_id=? AND category=?", (user["id"], a["category"])))):
            continue
        mine = set()
        if user:
            mine = {x["action"] for x in rows(db().execute("SELECT action FROM alert_engagement WHERE alert_id=? AND user_id=?", (a["id"], user["id"])))}
        out.append({"id": a["id"], "severity": a["severity"], "category": a["category"], "category_label": CATEGORIES[a["category"]],
                    "content": a["content"], "brands": a["brands"], "published": a["published"], "expires": a["expires"],
                    "demo": bool(a["demo"]), "acknowledged": "acknowledged" in mine})
    return out


def engage(aid, user, action):
    if action not in ("opened", "acknowledged", "reported_related"):
        raise AlertError("Unknown action")
    a = _load(aid)
    if a["status"] != "published":
        raise AlertError("This alert is not active")
    db().execute("INSERT OR IGNORE INTO alert_engagement VALUES (?,?,?,?)", (aid, user["id"], action, time.time()))
    db().commit()
    return {"ok": True}


def ai_draft(category: str, brands: list[str], signals: list[str] | None = None) -> dict:
    """Structured draft from MIRA's own guidance templates (and the optional LLM if configured). It is a draft: it is
    labelled as AI-generated and must be reviewed, translated and approved by people before anything is published."""
    if category not in CATEGORIES:
        raise AlertError("Unknown category")
    en_cat, ar_cat = CATEGORIES[category]
    brand = ", ".join(brands[:3]) if brands else ""
    en = {
        "title": f"Warning: {en_cat.lower()}" + (f" using the name of {brand}" if brand else ""),
        "description": (f"MIRA analysts are seeing {en_cat.lower()}" + (f" that pretend to come from {brand}" if brand else "") +
                        ". The messages look official and push you to act quickly."),
        "warning_signs": ["The link is not the organisation's official website", "You are rushed with a deadline or a fine",
                          "You are asked for card details, a one-time code or your password"] + (signals or [])[:3],
        "what_to_do": ["Do not open the link", "Open the service from its official app or by typing the official address",
                       "Report the message in MIRA Protect"],
        "never_share": ["One-time codes (OTP)", "Card number, expiry date or CVV", "Your passwords"],
        "official_resources": ["Abu Dhabi Police Aman service: 8002626 or SMS 2828"],
    }
    ar = {
        "title": f"تحذير: {ar_cat}" + (f" باسم {brand}" if brand else ""),
        "description": f"يرصد محللو ميرا {ar_cat}" + (f" تنتحل صفة {brand}" if brand else "") + ". تبدو الرسائل رسمية وتدفعك إلى التصرف بسرعة.",
        "warning_signs": ["الرابط ليس الموقع الرسمي للجهة", "يتم استعجالك بمهلة أو مخالفة", "يُطلب منك بيانات البطاقة أو رمز التحقق أو كلمة المرور"],
        "what_to_do": ["لا تفتح الرابط", "افتح الخدمة من تطبيقها الرسمي أو بكتابة العنوان الرسمي", "أبلغ عن الرسالة في ميرا بروتكت"],
        "never_share": ["رموز التحقق لمرة واحدة", "رقم البطاقة وتاريخ الانتهاء ورمز CVV", "كلمات المرور"],
        "official_resources": ["خدمة أمان لشرطة أبوظبي: 8002626 أو رسالة نصية إلى 2828"],
    }
    return {"content": {"en": en, "ar": ar}, "ai_drafted": True,
            "notice": "AI-assisted draft from MIRA's guidance templates. It is not an official statement: review, edit and approve it before publishing."}
