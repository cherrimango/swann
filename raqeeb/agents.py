"""RAQEEB Intelligence Engine: ten specialised agents with structured findings.

Every agent is deterministic code we own, so the system keeps working with no AI provider at all. An optional
OpenAI-compatible endpoint (e.g. a local Ollama server) can write plainer-language summaries: set RAQEEB_LLM_URL
and RAQEEB_LLM_MODEL. Agents never block anything or make official statements; they recommend, and the policy
layer (raqeeb.protection) decides.
"""
import datetime as dt
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field

import requests

from .brands import BRANDS
from .campaigns import kit_signature
from .db import db, rows
from .engine import scan_many
from .intel import EMAIL_RX, PHONE_RX, normalize_phone
from .messages import URL_RX, check_message
from .urlparse import parse


@dataclass
class Finding:
    agent: str
    subject: str
    confidence: float
    reasoning: str
    evidence: dict = field(default_factory=dict)
    source: str = "raqeeb"
    next_action: str = ""
    timestamp: float = field(default_factory=time.time)

    def save(self):
        db().execute("INSERT INTO findings (agent, subject, confidence, evidence, reasoning, source, next_action, created) VALUES (?,?,?,?,?,?,?,?)",
                     (self.agent, self.subject[:300], self.confidence, json.dumps(self.evidence, default=str)[:20000],
                      self.reasoning[:2000], self.source, self.next_action[:300], self.timestamp))
        return self


# ---------- optional LLM adapter ----------
def llm(prompt: str, max_tokens: int = 400) -> str | None:
    url, model = os.environ.get("RAQEEB_LLM_URL"), os.environ.get("RAQEEB_LLM_MODEL", "llama3.1")
    if not url:
        return None
    try:
        r = requests.post(url.rstrip("/") + "/v1/chat/completions", timeout=20,
                          headers={"Authorization": f"Bearer {os.environ.get('RAQEEB_LLM_KEY', 'none')}"},
                          json={"model": model, "max_tokens": max_tokens, "temperature": 0.2,
                                "messages": [{"role": "system", "content": "You write short, factual cyber-threat summaries for UAE police analysts. Never state guilt; describe evidence."},
                                             {"role": "user", "content": prompt}]})
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception:  # noqa: BLE001 - provider down: deterministic output is used instead
        return None


# ---------- extraction ----------
def extract(text: str) -> dict:
    text = text or ""
    urls = []
    for m in URL_RX.finditer(text):
        u = m.group(0).rstrip(").,;!؟،")
        if u not in urls and not EMAIL_RX.fullmatch(u):
            urls.append(u)
    emails = sorted(set(EMAIL_RX.findall(text)))
    urls = [u for u in urls if not any(u in e for e in emails)]
    phones = []
    for m in PHONE_RX.finditer(text):
        n = normalize_phone(m.group(0))
        if n and n not in phones and not any(m.group(0) in u for u in urls):
            phones.append(n)
    return {"urls": urls[:10], "phones": phones[:5], "emails": emails[:5]}


def detect_type(text: str, given: str | None, has_image: bool) -> str:
    if given and given != "auto":
        return given
    ex = extract(text)
    stripped = (text or "").strip()
    if has_image and not stripped:
        return "ad"
    if ex["phones"] and not ex["urls"] and len(stripped) < 25:
        return "phone"
    if ex["urls"] and len(stripped.split()) <= 2:
        return "website"
    if re.search(r"(?im)^(from|subject|to):", stripped) or ex["emails"]:
        return "email"
    return "sms" if stripped else "other"


# ---------- Agent 2: Phishing intelligence ----------
def phishing_agent(urls: list[str]) -> tuple[list[dict], list[Finding]]:
    results = scan_many(urls) if urls else []
    findings = []
    for r in results:
        b = r.get("impersonated_brand") or {}
        findings.append(Finding("phishing_intelligence", r["url"], round(r["risk_score"] / 100, 3),
                                "; ".join(x["en"] for x in r["reasons"][:3]) or "No risk signals",
                                {"risk": r["risk_score"], "verdict": r["verdict"], "brand": b.get("name"), "host": r["host"]},
                                next_action="verify and consider blocking" if r["label"] else "monitor"))
    return results, findings


# ---------- Agent 3: Message intelligence ----------
EMAIL_SPOOF = re.compile(r"(?im)^from:.*@(gmail|outlook|hotmail|yahoo|proton|mail)\.", re.M)


def message_agent(text: str) -> tuple[dict, Finding]:
    m = check_message(text)
    extra = []
    if EMAIL_SPOOF.search(text or "") and m["brands_named"]:
        m["risk_score"] = max(m["risk_score"], 70.0)
        extra.append("claims to be an organisation but was sent from a free email service")
    reasons = [s["en"] for s in m["script_signals"]] + extra
    return m, Finding("message_intelligence", (text or "")[:80], round(m["risk_score"] / 100, 3),
                      "; ".join(reasons) or "No scam-script signals", {"signals": [s["code"] for s in m["script_signals"]],
                                                                         "brands_named": m["brands_named"]},
                      next_action="correlate links and numbers" if m["risk_score"] >= 50 else "keep for pattern analysis")


# ---------- Agent 4: Advertisement intelligence ----------
AD_RULES = [
    ("discount", r"\b([5-9]\d)\s?%\s?(off|discount)|خصم\s?([5-9]\d)", 18, "Very large discount"),
    ("investment", r"guaranteed (returns?|profit)|monthly income|passive income|double your|ربح مضمون|دخل شهري", 30, "Investment promise"),
    ("gov_reward", r"government (grant|support|reward|compensation)|منحة حكومية|دعم حكومي", 30, "Fake government reward"),
    ("job_fee", r"(registration|processing|visa) fee|work from home.*(aed|dh)|رسوم (تسجيل|تأشيرة)", 25, "Job offer that charges a fee"),
    ("payment", r"\b(iban|bank transfer|usdt|crypto|bitcoin|gift card|western union)\b|تحويل بنكي", 22, "Unusual payment instructions"),
    ("urgency", r"\b(today only|last \d+|limited (seats|offer)|only \d+ left)\b|لفترة محدودة", 12, "Artificial urgency"),
]


def ad_agent(text: str, urls_result: list[dict]) -> tuple[dict, Finding]:
    hits, score = [], 0
    for code, rx, w, en in AD_RULES:
        if re.search(rx, text or "", re.I):
            hits.append({"code": code, "en": en})
            score += w
    link_risk = max((r["risk_score"] for r in urls_result), default=0)
    risk = min(100.0, max(link_risk, score * 1.5))
    out = {"risk": risk, "signals": hits}
    return out, Finding("advertisement_intelligence", (text or "")[:80], round(risk / 100, 3),
                        "; ".join(h["en"] for h in hits) or "No advertisement scam signals", out,
                        next_action="match the advertised site against known campaigns")


# ---------- Agent 5: Phone intelligence ----------
def phone_agent(phone: str) -> tuple[dict, Finding]:
    n = normalize_phone(phone) or phone
    reports = db().execute("SELECT COUNT(*) FROM threats WHERE indicator_type='phone' AND normalized=?", (n,)).fetchone()[0]
    t = rows(db().execute("SELECT id, status, report_count, risk FROM threats WHERE indicator_type='phone' AND normalized=?", (n,)))
    signals, risk = [], 20.0
    if n.startswith("+971"):
        kind = "UAE mobile" if n.startswith("+9715") else "UAE landline"
    else:
        kind = "International"
        signals.append("International number: UAE banks and government call from UAE numbers")
        risk += 20
    if t:
        risk = max(risk, t[0]["risk"] or 0)
        signals.append(f"Reported {t[0]['report_count']} time(s) before")
        risk += min(30, 8 * t[0]["report_count"])
        if t[0]["status"] == "confirmed_malicious":
            risk = 95.0
            signals.append("Confirmed scam number")
    out = {"number": n, "kind": kind, "signals": signals, "risk": min(100.0, risk), "known": bool(reports)}
    return out, Finding("phone_intelligence", n, round(out["risk"] / 100, 3), "; ".join(signals) or kind, out,
                        next_action="corroborate with other reports" if reports else "watch for repeats")


# ---------- Agent 6: Campaign correlation ----------
def _shingles(text: str) -> set:
    words = re.findall(r"\w+", (text or "").lower())
    words = [w for w in words if not w.isdigit()]
    return {" ".join(words[i:i + 3]) for i in range(max(0, len(words) - 2))}


def correlate() -> dict:
    """Group threats into campaigns: shared domain, co-occurrence in one report (link + number + sender), the same
    phishing kit, or near-identical message text. Returns the investigation graph."""
    threats = rows(db().execute("SELECT id, indicator_type, normalized, brand, category, campaign_id FROM threats"))
    reports = rows(db().execute("SELECT id, raw_text, threat_ids FROM citizen_reports WHERE threat_ids IS NOT NULL"))
    parent = {t["id"]: t["id"] for t in threats}
    reasons = []

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b, why):
        if a in parent and b in parent and a != b:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra
            reasons.append({"source": a, "target": b, "reason": why})

    by_key = {}
    for t in threats:
        if t["indicator_type"] in ("url", "domain", "qr"):
            p = parse("http://" + t["normalized"])
            by_key.setdefault(("domain", p.registered_domain), []).append(t["id"])
            sig = kit_signature("http://" + t["normalized"])
            if sig:
                by_key.setdefault(("kit", sig), []).append(t["id"])
    for (kind, _), ids in by_key.items():
        for other in ids[1:]:
            union(ids[0], other, "same domain" if kind == "domain" else "same phishing kit")
    for r in reports:
        ids = [i for i in json.loads(r["threat_ids"] or "[]") if i in parent]
        for other in ids[1:]:
            union(ids[0], other, "seen together in one report")
    sh = [(r, _shingles(r["raw_text"])) for r in reports if len(_shingles(r["raw_text"])) >= 4]
    for i in range(len(sh)):
        for j in range(i + 1, len(sh)):
            a, b = sh[i][1], sh[j][1]
            if len(a & b) / max(1, len(a | b)) >= 0.5:
                ia, ib = json.loads(sh[i][0]["threat_ids"] or "[]"), json.loads(sh[j][0]["threat_ids"] or "[]")
                if ia and ib:
                    union(ia[0], ib[0], "near-identical message text")
    groups = {}
    for t in threats:
        groups.setdefault(find(t["id"]), []).append(t)
    campaigns = []
    for root, members in groups.items():
        cid = f"CMP-{root.split('-')[-1]}" if len(members) > 1 else None
        for m in members:
            if m["campaign_id"] != cid:
                db().execute("UPDATE threats SET campaign_id=? WHERE id=?", (cid, m["id"]))
        if cid:
            campaigns.append({"id": cid, "threats": [m["id"] for m in members],
                              "brands": sorted({m["brand"] for m in members if m["brand"]}),
                              "types": sorted({m["indicator_type"] for m in members})})
    nodes = [{"id": t["id"], "kind": t["indicator_type"], "label": t["normalized"][:60], "brand": t["brand"],
              "campaign": find(t["id"]) if len(groups[find(t["id"])]) > 1 else None} for t in threats]
    return {"campaigns": sorted(campaigns, key=lambda c: -len(c["threats"])), "graph": {"nodes": nodes, "edges": reasons}}


# ---------- Agent 7: Seasonal intelligence ----------
EXTRA_SEASONS = [  # dates for moon-sighted holidays are approximate and labelled so
    {"id": "winter_camping", "name": "Winter camping and desert season (Nov–Mar)", "name_ar": "موسم التخييم الشتوي والبر (نوفمبر–مارس)",
     "months": [11, 12, 1, 2, 3], "categories": ["fraud_ad", "fake_payment", "fake_gov"],
     "keywords": ["camp", "camping", "safari", "desert", "glamping", "permit", "تخييم", "رحلة سفاري", "تصريح"],
     "advice": "Warn about fake camping permits, desert-safari deals and equipment sellers that ask for transfers."},
    {"id": "winter_tourism", "name": "Winter tourism, hotels and events", "name_ar": "السياحة الشتوية والفنادق والفعاليات",
     "months": [11, 12, 1, 2], "categories": ["fraud_ad", "fake_payment"], "keywords": ["hotel", "booking", "staycation", "ticket", "festival"],
     "advice": "Warn about fake hotel bookings, staycation deals and event tickets sold on social media."},
    {"id": "ramadan", "name": "Ramadan (approx. Feb–Mar 2027)", "name_ar": "رمضان (تقريباً فبراير–مارس 2027)", "months": [2, 3],
     "categories": ["fake_payment", "fraud_ad", "impersonation"], "advice": "Warn about fake charity, iftar-box and Zakat collection links."},
    {"id": "eid_fitr", "name": "Eid Al Fitr (approx. Mar 2027)", "name_ar": "عيد الفطر (تقريباً مارس 2027)", "months": [3],
     "categories": ["fraud_ad", "delivery_customs", "fake_payment"], "advice": "Warn about Eid gift, Eidiya transfer and travel deals."},
    {"id": "eid_adha", "name": "Eid Al Adha (approx. May 2027)", "name_ar": "عيد الأضحى (تقريباً مايو 2027)", "months": [5],
     "categories": ["fraud_ad", "fake_payment"], "advice": "Abu Dhabi Police have warned of fake Eid catering and meat offers."},
    {"id": "back_to_school", "name": "Back to school", "name_ar": "العودة إلى المدارس", "months": [8, 9],
     "categories": ["fraud_ad", "fake_payment"], "advice": "Warn about fake school-fee portals and uniform deals."},
    {"id": "white_friday", "name": "White Friday and shopping events", "name_ar": "الجمعة البيضاء ومواسم التسوق", "months": [11],
     "categories": ["fraud_ad", "delivery_customs"], "advice": "Warn about fake stores and delivery-fee messages."},
    {"id": "visa_renewal", "name": "Visa and Emirates ID renewals (year-round)", "name_ar": "تجديد التأشيرات والهوية (طوال العام)",
     "months": list(range(1, 13)), "categories": ["fake_gov"], "advice": "Remind residents ICP services are only on the ICP app and site."},
]


def seasonal_agent(today: dt.date | None = None) -> dict:
    from .scamcast import active, predicted_domains
    today = today or dt.date.today()
    now = time.time()
    confirmed = rows(db().execute("""SELECT category, COUNT(*) n FROM threats WHERE status='confirmed_malicious'
                                  AND last_seen >= ? GROUP BY category ORDER BY n DESC""", (now - 30 * 86400,)))
    this_week = dict(db().execute("SELECT type, COUNT(*) FROM citizen_reports WHERE created >= ? GROUP BY type", (now - 7 * 86400,)).fetchall())
    last_week = dict(db().execute("SELECT type, COUNT(*) FROM citizen_reports WHERE created >= ? AND created < ? GROUP BY type",
                                  (now - 14 * 86400, now - 7 * 86400)).fetchall())
    observed = [{"report_type": k, "this_week": v, "last_week": last_week.get(k, 0)}
                for k, v in this_week.items() if v >= 2 and v > 1.5 * last_week.get(k, 0)]
    predicted = [{"season": s["name"], "season_ar": s["name_ar"], "watchlist": predicted_domains(s)[:6], "basis": "domain-name forecast"}
                 for s in active(today)]
    for s in EXTRA_SEASONS:
        if today.month not in s["months"]:
            continue
        signals = {"real": 0, "demo": 0}
        for kw in s.get("keywords", []):
            for demo, n in db().execute("""SELECT demo, COUNT(*) FROM threats WHERE last_seen >= ? AND (normalized LIKE ? OR original LIKE ?)
                                           GROUP BY demo""", (now - 30 * 86400, f"%{kw}%", f"%{kw}%")).fetchall():
                signals["demo" if demo else "real"] += n
        predicted.append({"season": s["name"], "season_ar": s["name_ar"], "categories": s["categories"], "advice": s["advice"],
                          "basis": "seasonal pattern", "observed_signals_30d": signals})
    return {
        "confirmed_current": confirmed,          # confirmed by analysts in the last 30 days
        "observed_emerging": observed,           # reporting volume rising week over week
        "predicted": predicted,                  # forecasts only: never shown as active scams
        "historical_associations": [{"season": s["name"], "categories": s["categories"]} for s in EXTRA_SEASONS],
        "note": "Predictions are forecasts based on seasonal patterns and domain-name generation. They are not confirmed scams.",
    }


# ---------- Agent 8: Community intelligence ----------
def community_agent(user_id: int | None, normalized_indicators: list[str]) -> dict:
    if not user_id:
        return {"duplicate_of": None, "flags": []}
    flags = []
    day = db().execute("SELECT COUNT(*) FROM citizen_reports WHERE user_id=? AND created >= ?", (user_id, time.time() - 86400)).fetchone()[0]
    if day >= 25:
        flags.append("unusually many reports in 24 hours")
    bad = db().execute("SELECT COUNT(*) FROM citizen_reports WHERE user_id=? AND status IN ('rejected','false_positive') AND created >= ?",
                       (user_id, time.time() - 7 * 86400)).fetchone()[0]
    if bad >= 3:
        flags.append("several recent reports were rejected")
    dup = None
    for ind in normalized_indicators:
        prev = db().execute("SELECT ref FROM citizen_reports WHERE user_id=? AND indicators LIKE ? ORDER BY created LIMIT 1",
                            (user_id, f'%"{ind}"%')).fetchone()
        if prev:
            dup = prev[0]
            break
    return {"duplicate_of": dup, "flags": flags}


# ---------- Agent 9: Intelligence briefing ----------
def briefing_agent(period: str = "day") -> dict:
    span = {"day": 86400, "week": 7 * 86400, "month": 30 * 86400}.get(period, 86400)
    since = time.time() - span
    q = lambda sql, *a: db().execute(sql, a).fetchone()[0]  # noqa: E731
    data = {
        "period": period, "generated": time.time(),
        "new_threats": q("SELECT COUNT(*) FROM threats WHERE first_seen >= ?", since),
        "confirmed": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious' AND last_seen >= ?", since),
        "awaiting_review": q("SELECT COUNT(*) FROM threats WHERE status IN ('under_review','community_corroborated')"),
        "awaiting_block_approval": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious' AND block_status!='global'"),
        "citizen_reports": q("SELECT COUNT(*) FROM citizen_reports WHERE created >= ?", since),
        "blocked_now": q("SELECT COUNT(*) FROM threats WHERE block_status='global'"),
        "top_brands": rows(db().execute("SELECT brand, COUNT(*) n FROM threats WHERE brand != '' AND last_seen >= ? GROUP BY brand ORDER BY n DESC LIMIT 5", (since,))),
        "top_categories": rows(db().execute("SELECT category, COUNT(*) n FROM threats WHERE last_seen >= ? GROUP BY category ORDER BY n DESC LIMIT 5", (since,))),
        "campaigns": rows(db().execute("SELECT campaign_id, COUNT(*) n FROM threats WHERE campaign_id IS NOT NULL GROUP BY campaign_id ORDER BY n DESC LIMIT 5")),
    }
    actions = []
    if data["awaiting_block_approval"]:
        actions.append(f"Approve or reject {data['awaiting_block_approval']} confirmed threats waiting for a blocking decision.")
    if data["awaiting_review"]:
        actions.append(f"Review {data['awaiting_review']} threats in the verification queue, corroborated ones first.")
    if data["top_brands"]:
        b = data["top_brands"][0]
        actions.append(f"Consider a public alert: {b['brand']} is the most impersonated brand this {period} ({b['n']} threats).")
    data["recommended_actions"] = actions
    text = (f"In the last {period}, RAQEEB recorded {data['new_threats']} new threats and {data['citizen_reports']} citizen reports. "
            f"{data['confirmed']} confirmed malicious; {data['blocked_now']} currently blocked for all users. "
            + (f"Most impersonated: {', '.join(b['brand'] for b in data['top_brands'][:3])}. " if data["top_brands"] else ""))
    data["summary"] = llm("Summarise this RAQEEB threat data for police analysts in 4 sentences:\n" + json.dumps(data, default=str)) or text
    data["summary_source"] = "llm" if os.environ.get("RAQEEB_LLM_URL") and data["summary"] != text else "rules"
    Finding("intelligence_briefing", f"{period} briefing", 1.0, data["summary"], {"period": period}).save()
    return data


# ---------- Agent 10: Protection distribution ----------
def distribution_agent() -> list[dict]:
    """Threats ready for an approver: confirmed malicious, not yet blocked. Recommends only; never publishes."""
    return rows(db().execute("""SELECT id, normalized, indicator_type, brand, risk, report_count FROM threats
        WHERE status='confirmed_malicious' AND block_status NOT IN ('global') ORDER BY risk DESC LIMIT 50"""))


# ---------- Agent 1: Threat hunter (wraps raqeeb.hunt; run from the server's background jobs) ----------
def hunter_finding(domain: str, result: dict, source: str) -> Finding:
    return Finding("threat_hunter", domain, round(result["risk_score"] / 100, 3),
                   result["reasons"][0]["en"] if result["reasons"] else "No signals",
                   {"risk": result["risk_score"], "verdict": result["verdict"]}, source=source,
                   next_action="add to early threat watch" if result["risk_score"] >= 35 else "ignore")


AGENTS = ["threat_hunter", "phishing_intelligence", "message_intelligence", "advertisement_intelligence",
          "phone_intelligence", "campaign_correlation", "seasonal_intelligence", "community_intelligence",
          "intelligence_briefing", "protection_distribution"]


def brand_sector(name: str | None) -> str | None:
    return next((b["sector"] for b in BRANDS if b["name"] == name), None)


def as_dict(f: Finding) -> dict:
    return asdict(f)
