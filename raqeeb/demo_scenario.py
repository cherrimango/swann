"""Hackathon demonstration mode (RAQEEB_DEMO=1): demo accounts and the seeded "fake winter camping promotion" scenario.

Everything created here is marked as demonstration data (threats.demo = 1, sources say "DEMO SEED", accounts end in
@raqeeb.demo). The discovery in step 1 is simulated; every analysis after it is RAQEEB's real engine running on the
seeded indicators. Steps 6-11 are done live by the presenter in COMMAND and PROTECT; their progress is read from the
database, not pretended.
"""
import json
import os
import time

from . import agents, auth, community, intel, store
from .db import db, one, rows
from .link import pipeline

DEMO_ACCOUNTS = [  # demonstration-only credentials; never use them outside a demo
    {"label": "Command administrator", "email": "admin@raqeeb.demo", "password": "RaqeebDemo2026!", "role": "super_admin",
     "name": "Demo Administrator", "app": "command"},
    {"label": "Cybercrime analyst", "email": "analyst@raqeeb.demo", "password": "AnalystDemo2026!", "role": "cyber_analyst",
     "name": "Demo Analyst", "app": "command"},
    {"label": "Citizen", "email": "citizen@raqeeb.demo", "password": "CitizenDemo2026!", "role": "citizen",
     "name": "Demo Citizen", "app": "protect", "emirate": "Abu Dhabi"},
]
SCENARIO = {
    "domain": "tamm-camping-permit.top",
    "payment_link": "https://tamm-camping-permit.top/permit/pay?season=winter",
    "related_domain": "desertcamp-booking-tamm.top",
    "phone": "+971500000001",
    "ad_text": ("Winter desert camping permit 2026 - official TAMM fast track. Book your family camp spot today only, "
                "70% OFF. Pay the AED 49 permit fee now: https://desertcamp-booking-tamm.top/book or WhatsApp +971 50 000 0001"),
    "sms_text": ("TAMM: Your winter camping permit is pending. Pay AED 49 today to avoid cancellation: "
                 "https://tamm-camping-permit.top/permit/pay?season=winter or call +971 50 000 0001"),
    "related_url": "https://desertcamp-booking-tamm.top/permit/pay",
}
STEPS = [
    ("discovery", "Domain Hunter discovers a newly observed look-alike domain (simulated discovery, seeded)"),
    ("static", "Link Intelligence Engine analyses the domain and payment link"),
    ("visual", "Visual impersonation check against verified references"),
    ("seasonal", "Seasonal agent matches it to the winter camping season and checks for real signals"),
    ("campaign", "Campaign agent links the payment link, a second domain and the phone number the messages share"),
    ("verify", "An analyst reviews the evidence and marks it Analyst verified"),
    ("approve", "An authorised official approves it (Officially approved)"),
    ("distribute", "Global block approved: a new signed protection version reaches every device"),
    ("citizen_check", "A citizen pastes the payment link in RAQEEB PROTECT and is warned"),
    ("community", "The citizen reports the related advert; the community agent links it to the campaign"),
    ("command_update", "COMMAND shows the new evidence, the points awarded and the campaign timeline"),
]


def enabled() -> bool:
    return os.environ.get("RAQEEB_DEMO", "").lower() in ("1", "true", "yes")


def ensure_accounts():
    for a in DEMO_ACCOUNTS:
        if not one(db().execute("SELECT id FROM users WHERE email=?", (a["email"],))):
            auth.create_user(a["email"], a["password"], a["role"], a["name"], a.get("emirate"), True)


def public_accounts() -> list[dict]:
    return [{k: a[k] for k in ("label", "email", "password", "app")} for a in DEMO_ACCOUNTS]


def _user(email):
    u = one(db().execute("SELECT id FROM users WHERE email=?", (email,)))
    return auth.get_user(u["id"]) if u else None


def _main_threat():
    return intel.find("url", SCENARIO["payment_link"]) or intel.find("domain", SCENARIO["domain"])


def seed() -> dict:
    """Run steps 1-5. Safe to call twice: existing records are reused."""
    ensure_accounts()
    log = []
    # 1. discovery (simulated) -> hunt feed + threat record + finding
    core = pipeline.core_scan(SCENARIO["domain"])
    store.add_feed(SCENARIO["domain"], SCENARIO["domain"], (core.get("impersonated_brand") or {}).get("name", ""), core["risk_score"],
                   core["verdict"], "DEMO SEED: Domain Hunter (simulated new-domain discovery)",
                   core["reasons"][0]["en"] if core["reasons"] else "")
    agents.hunter_finding(SCENARIO["domain"], core, "DEMO SEED: simulated discovery").save()
    log.append(f"Discovered {SCENARIO['domain']} (simulated); engine risk {core['risk_score']}")
    # 2. static analysis of the payment link (real engine)
    rep = pipeline.analyse(SCENARIO["payment_link"], "quick")
    pipeline.save(rep, None)
    brand = rep["detected_brand"] or ""
    t, _ = intel.upsert("url", SCENARIO["payment_link"], intel.category_for("url", agents.brand_sector(brand), "website"), brand,
                        rep["risk_score"], rep["risk_score"] / 100,
                        {"scan_id": rep["scan_id"], "verdict": rep["verdict"], "reasons": [e["detail_en"] for e in rep["strongest_indicators"]],
                         "note": "DEMO SEED"}, "Abu Dhabi", source="DEMO SEED: Domain Hunter + Link Intelligence Engine", status="new",
                        actor="demo-seed")
    db().execute("UPDATE threats SET demo=1 WHERE id=?", (t["id"],))
    if t["status"] == "new":
        intel.set_status(t["id"], "under_review", "demo-seed", f"Link engine verdict {rep['verdict']} ({rep['risk_score']})")
    log.append(f"{t['id']}: link engine {rep['verdict']} {rep['risk_score']} ({rep['scan_id']})")
    # 3. visual: reported honestly; the demo page is not hosted, so there is no screenshot to compare
    intel.add_history(t["id"], {"event": "visual_check", "by": "demo-seed",
                                "note": "Visual comparison needs a deep scan of a live page and verified reference screenshots; not run in the offline demo."})
    # 4. seasonal
    season = next((p for p in agents.seasonal_agent()["predicted"] if p["season"].startswith("Winter camping")), None)
    if season:
        agents.Finding("seasonal_intelligence", "Winter camping season", 0.6,
                       f"Season active. Supporting signals in the last 30 days: {season['observed_signals_30d']['real']} real, "
                       f"{season['observed_signals_30d']['demo']} demo-seeded. This is a seasonal risk, not proof of a scam.",
                       season, source="DEMO SEED", next_action="watch camping/safari look-alikes").save()
        log.append(f"Seasonal signals: {season['observed_signals_30d']}")
    # 5. campaign: a demo citizen reports the SMS with the link; another reports the advert with a second domain + phone
    ensure_accounts()
    helpers = []
    for i in range(1, 3):
        email = f"helper{i}@raqeeb.demo"
        if not _user(email):
            auth.create_user(email, f"demo-helper-{i}-pass", "citizen", f"Demo Helper {i}", "Dubai" if i == 1 else "Sharjah", True)
        helpers.append(_user(email))
    if not rows(db().execute("SELECT id FROM citizen_reports WHERE raw_text=?", (SCENARIO["sms_text"],))):
        community.submit(helpers[0], "sms", SCENARIO["sms_text"], helpers[0]["emirate"])
        # the same scammers rotate to a second domain; the phone number stays the same
        community.submit(helpers[1], "sms", SCENARIO["sms_text"].replace(SCENARIO["payment_link"], SCENARIO["related_url"]), helpers[1]["emirate"])
    # the hunter also finds a second domain serving the same kit path (simulated discovery, real analysis)
    rel = pipeline.analyse(SCENARIO["related_url"], "quick")
    pipeline.save(rel, None)
    t2, _ = intel.upsert("url", SCENARIO["related_url"], "fraud_ad", rel["detected_brand"] or "", rel["risk_score"], rel["risk_score"] / 100,
                         {"scan_id": rel["scan_id"], "note": "DEMO SEED"}, None, source="DEMO SEED: Domain Hunter (simulated discovery)",
                         actor="demo-seed")
    for tid in [r["id"] for r in rows(db().execute("SELECT id FROM threats WHERE normalized LIKE '%tamm-camping%' OR normalized LIKE '%desertcamp%' "
                                                   "OR normalized = ?", (SCENARIO["phone"],)))]:
        db().execute("UPDATE threats SET demo=1 WHERE id=?", (tid,))
    g = agents.correlate()
    t = _main_threat()
    camp = next((c for c in g["campaigns"] if t["id"] in c["threats"]), None)
    log.append(f"Campaign {camp['id'] if camp else '-'}: {len(camp['threats']) if camp else 0} linked indicators")
    db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,?,?)", ("demo_seed", json.dumps(log), time.time(), "demo-seed"))
    return {"log": log, "status": status()}


def status() -> dict:
    t = _main_threat()
    done = {k: False for k, _ in STEPS}
    if t:
        hist = [h.get("event") for h in t["history"]]
        done["discovery"] = done["static"] = True
        done["visual"] = "visual_check" in hist
        done["seasonal"] = bool(one(db().execute("SELECT id FROM findings WHERE agent='seasonal_intelligence' AND source='DEMO SEED'")))
        done["campaign"] = bool(t["campaign_id"])
        done["verify"] = any(h.get("to") == "analyst_verified" for h in t["history"])
        done["approve"] = any(h.get("to") == "confirmed_malicious" for h in t["history"])
        done["distribute"] = t["block_status"] == "global"
        done["citizen_check"] = bool(one(db().execute("SELECT value FROM metrics WHERE key='demo_citizen_check'")))
        c1 = _user("citizen@raqeeb.demo")
        if c1:
            done["community"] = bool(one(db().execute("SELECT id FROM citizen_reports WHERE user_id=? AND raw_text LIKE '%desertcamp%'", (c1["id"],))))
            done["command_update"] = done["community"] and bool(one(db().execute(
                "SELECT id FROM points WHERE user_id=? AND delta > 0", (c1["id"],))))
    return {"enabled": enabled(), "threat_id": t["id"] if t else None, "campaign_id": t["campaign_id"] if t else None,
            "steps": [{"id": k, "title": title, "done": done[k]} for k, title in STEPS], "scenario": SCENARIO}


def note_citizen_check(text: str):
    if SCENARIO["domain"] in (text or "") or SCENARIO["related_domain"] in (text or ""):
        db().execute("INSERT INTO metrics (key, value) VALUES ('demo_citizen_check', 1) ON CONFLICT(key) DO UPDATE SET value = value + 1")


def reset():
    """Remove all demo-seeded records (threats, reports, findings, demo-account activity). Real data is untouched."""
    demo_users = [r["id"] for r in rows(db().execute("SELECT id FROM users WHERE email LIKE '%@raqeeb.demo'"))]
    ids = {r["id"] for r in rows(db().execute("SELECT id FROM threats WHERE demo=1"))}
    by_users: dict[str, set] = {}
    for r in rows(db().execute("SELECT user_id, threat_ids FROM citizen_reports WHERE threat_ids IS NOT NULL")):
        for tid in json.loads(r["threat_ids"]):
            by_users.setdefault(tid, set()).add(r["user_id"] in demo_users)
    ids |= {tid for tid, kinds in by_users.items() if kinds == {True}}  # reported only by demo accounts
    ids = sorted(ids)
    for tid in ids:
        db().execute("DELETE FROM corroborations WHERE threat_id=?", (tid,))
        db().execute("DELETE FROM investigation_notes WHERE threat_id=?", (tid,))
    if ids:
        db().execute(f"DELETE FROM threats WHERE id IN ({','.join('?' * len(ids))})", ids)
    if demo_users:
        q = ",".join("?" * len(demo_users))
        for table in ("citizen_reports", "points", "badges", "personal_blocks", "notifications", "learning", "corroborations"):
            db().execute(f"DELETE FROM {table} WHERE user_id IN ({q})", demo_users)
    db().execute("DELETE FROM findings WHERE source LIKE 'DEMO SEED%'")
    db().execute("DELETE FROM feed WHERE source LIKE 'DEMO SEED%'")
    db().execute("DELETE FROM metrics WHERE key='demo_citizen_check'")
    from . import protection
    protection.publish("demo-seed", "Demo data reset")
    return {"removed_threats": len(ids)}
