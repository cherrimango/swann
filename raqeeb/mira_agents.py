"""The fourteen MIRA agents behind one contract.

Every agent returns the same envelope:
    agent, task, result, evidence, confidence (0-1 or null), source, timestamp (UTC ISO), limitations, recommended_action
Agents analyse and recommend. None of them can approve a threat, block anything globally or publish an alert: those
actions stay with authorised people in MIRA Command. Each agent wraps a real MIRA component; an agent whose input or
data is missing says so in `limitations` instead of producing a result.
"""
import datetime as dt
import json
import time

from . import agents as core
from .db import db, rows


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _env(agent, task, result, evidence, confidence, source, limitations, action):
    return {"agent": agent, "task": task, "result": result, "evidence": evidence, "confidence": confidence, "source": source,
            "timestamp": _now(), "limitations": limitations, "recommended_action": action}


def _scan(url, mode="quick"):
    from .link import pipeline
    r = pipeline.analyse(url, mode)
    pipeline.save(r, None)
    return r


def threat_hunter(_=None):
    from . import discovery
    st = discovery.status()
    new = rows(db().execute("SELECT value, source, first_seen FROM indicators ORDER BY first_seen DESC LIMIT 15"))
    healthy = [s["name"] for s in st["sources"] if s["health"] == "healthy"]
    lim = [] if healthy else ["No feed has been collected successfully yet; run the Threat Discovery Engine."]
    return _env("Global Threat Hunter", "Collect new phishing indicators from permitted public feeds",
                {"indicators_total": st["indicators"]["total"], "new_last_24h": st["indicators"]["new_24h"], "healthy_sources": healthy},
                {"latest_indicators": new}, None, "MIRA Threat Discovery Engine", lim + ["Feed indicators are unverified leads."],
                "Review new UAE-relevant indicators in Live threat intelligence.")


def phishing(url):
    if not url:
        return _env("Phishing Intelligence", "Analyse a link", None, {}, None, "Link Intelligence Engine", ["Give a URL to analyse."], "")
    r = _scan(url)
    conf = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}.get(r["assessment_confidence"])
    return _env("Phishing Intelligence", f"Analyse {url[:120]}", {"verdict": r["verdict"], "risk_score": r["risk_score"], "scan_id": r["scan_id"]},
                r["strongest_indicators"], conf, "Link Intelligence Engine (quick scan)", r["limitations"], r["recommended_action"]["en"])


def brand_impersonation(url):
    if not url:
        return _env("UAE Brand Impersonation", "Check a link for brand impersonation", None, {}, None, "Brand registry", ["Give a URL."], "")
    from .brands import detect, official_brand
    from .urlparse import parse
    p = parse(url)
    off = official_brand(p)
    hits = detect(p)
    res = {"official_domain_of": off["name"] if off else None,
           "impersonates": [{"brand": h.brand_name, "match": h.kind, "matched": h.matched, "official_domains": h.official} for h in hits]}
    act = ("Escalate to Threat verification and compare with the official site." if hits else
           "No impersonation found in the address; a deep scan checks the page itself.")
    return _env("UAE Brand Impersonation", f"Check {url[:120]}", res, {"host": p.host, "registered_domain": p.registered_domain},
                0.85 if hits and hits[0].kind in ("host_keyword", "homoglyph", "typosquat") else (0.5 if hits else None),
                "MIRA brand registry (raqeeb/brands.json)", ["Only brands in the verified registry are recognised."], act)


def message(text):
    if not text:
        return _env("Message Intelligence", "Analyse a message", None, {}, None, "Message rules", ["Give the message text."], "")
    m, f = core.message_agent(text)
    return _env("Message Intelligence", "Analyse a message", {"verdict": m["verdict"], "risk_score": m["risk_score"]},
                {"script_signals": m["script_signals"], "links": [{"url": l["url"], "verdict": l["verdict"]} for l in m["links"]]},
                f.confidence, "MIRA scam-script rules (EN/AR) + link engine", ["Rules cover known scam scripts; new wording may be missed."],
                m["advice_en"])


def advertisement(text):
    if not text:
        return _env("Advertisement Intelligence", "Analyse an advert", None, {}, None, "Advert rules", ["Give the advert text."], "")
    m = core.check_message(text) if hasattr(core, "check_message") else {"links": []}
    out, f = core.ad_agent(text, m.get("links", []))
    return _env("Advertisement Intelligence", "Analyse an advert", out, f.evidence, f.confidence, "MIRA advert rules",
                ["Text rules only; images need the attachment analyser."], f.next_action or "Report the advert to the platform.")


def phone(number):
    if not number:
        return _env("Phone Intelligence", "Check a phone number", None, {}, None, "MIRA threat records", ["Give a phone number."], "")
    out, f = core.phone_agent(number)
    return _env("Phone Intelligence", f"Check {number[:30]}", out, f.evidence, f.confidence, "MIRA threat records and citizen reports",
                ["MIRA detects reported numbers; it never places or screens calls from the server."], f.next_action)


def qr(payload):
    if not payload:
        return _env("QR Intelligence", "Analyse a QR payload", None, {}, None, "QR decoder", ["Give the decoded QR text or upload an image to /api/v1/attachments/analyze."], "")
    if payload.lower().startswith(("http://", "https://", "www.")):
        r = _scan(payload)
        return _env("QR Intelligence", "Analyse a QR link", {"verdict": r["verdict"], "risk_score": r["risk_score"], "scan_id": r["scan_id"]},
                    r["strongest_indicators"], None, "Link Intelligence Engine", r["limitations"], r["recommended_action"]["en"])
    kind = "payment" if payload.lower().startswith(("upi:", "bitcoin:", "ethereum:")) else "wifi" if payload.startswith("WIFI:") else "text"
    return _env("QR Intelligence", "Analyse a QR payload", {"payload_type": kind}, {"payload": payload[:300]}, None, "QR decoder",
                ["Not a link: nothing to scan."], "Never pay or join networks from a QR code you did not expect.")


def sandbox(scan_id):
    from .link import pipeline
    r = pipeline.get(scan_id or "") if scan_id else None
    if not r or r.get("mode") != "deep":
        return _env("Sandbox Analysis", "Summarise a deep scan", None, {}, None, "MIRA sandbox", ["Give the scan ID of a completed deep scan."], "")
    sb = r.get("website_analysis") or {}
    return _env("Sandbox Analysis", f"Summarise {scan_id}", {"verdict": r.get("verdict"), "analysis_status": r.get("analysis_status"),
                "final_url": r.get("final_url"), "password_fields": sb.get("password_fields"), "payment_fields": sb.get("payment_fields")},
                {"redirects": r.get("redirects"), "forms": sb.get("forms")}, None, "Playwright Chromium sandbox",
                r.get("limitations", []), (r.get("recommended_action") or {}).get("en", ""))


def visual(scan_id):
    from .link import pipeline
    r = pipeline.get(scan_id or "") if scan_id else None
    vis = (r or {}).get("visual_analysis") or {}
    if not r:
        return _env("Visual Impersonation", "Compare a page with official references", None, {}, None, "Visual analyser", ["Give a deep-scan ID."], "")
    lim = [] if vis.get("available") else [vis.get("reason") or "Visual comparison did not run"]
    return _env("Visual Impersonation", f"Visual comparison for {scan_id}", {k: vis.get(k) for k in ("detected_brand", "overall_visual_similarity", "reference_used")},
                {"indicators": vis.get("indicators"), "missing_references": vis.get("missing_references")}, vis.get("overall_visual_similarity"),
                "pHash + layout + colour + OCR against verified references", lim + ["Visual similarity alone is not proof of a scam."],
                "Confirm with the domain and form evidence before acting.")


def campaigns(_=None):
    g = core.correlate()
    camps = g.get("campaigns", []) if isinstance(g, dict) else []
    return _env("Campaign Correlation", "Group related threats into campaigns", {"campaigns": len(camps)}, {"campaigns": camps[:20]}, None,
                "MIRA threat records", ["Links threats by shared domains, numbers, kits and message text only."], "Investigate the largest campaigns first.")


def seasonal(_=None):
    s = core.seasonal_agent()
    return _env("Seasonal Intelligence", "Seasonal scam outlook", s, {}, None, "Seasonal calendar + observed signals",
                ["Forecasts are predictions, not confirmed scams; each item states whether it is confirmed, emerging or predicted."],
                "Prepare citizen alerts for the active season.")


def community(_=None):
    q = rows(db().execute("SELECT status, COUNT(*) n FROM citizen_reports GROUP BY status"))
    return _env("Community Intelligence", "Citizen report health", {"reports_by_status": {r["status"]: r["n"] for r in q}}, {}, None,
                "MIRA Protect reports", ["Citizen reports are untrusted until reviewed and never retrain models automatically."],
                "Review reports waiting in the queue.")


def briefing(period="day"):
    b = core.briefing_agent(period if period in ("day", "week", "month") else "day")
    return _env("Intelligence Briefing", f"{period} briefing", b, {}, None, "MIRA records", ["Summarises recorded data only."], "Share with the duty officer.")


def distribution(_=None):
    d = core.distribution_agent()
    return _env("Protection Distribution", "Threats ready for blocking", {"ready": len(d)}, {"threats": d[:30]}, None, "MIRA threat records",
                ["Recommends only. Publishing protection needs an authorised approver."], "Open Blocking & distribution to approve.")


AGENTS = {
    "global_threat_hunter": ("Global Threat Hunter", None, threat_hunter),
    "phishing": ("Phishing Intelligence", "url", phishing),
    "uae_brand_impersonation": ("UAE Brand Impersonation", "url", brand_impersonation),
    "message": ("Message Intelligence", "text", message),
    "advertisement": ("Advertisement Intelligence", "text", advertisement),
    "phone": ("Phone Intelligence", "phone", phone),
    "qr": ("QR Intelligence", "qr payload", qr),
    "sandbox": ("Sandbox Analysis", "scan id", sandbox),
    "visual_impersonation": ("Visual Impersonation", "scan id", visual),
    "campaign_correlation": ("Campaign Correlation", None, campaigns),
    "seasonal": ("Seasonal Intelligence", None, seasonal),
    "community": ("Community Intelligence", None, community),
    "briefing": ("Intelligence Briefing", "period", briefing),
    "protection_distribution": ("Protection Distribution", None, distribution),
}


def catalogue():
    return [{"id": k, "name": n, "input": i} for k, (n, i, _) in AGENTS.items()]


def run(agent_id: str, value: str | None = None) -> dict:
    if agent_id not in AGENTS:
        raise KeyError(agent_id)
    t0 = time.time()
    out = AGENTS[agent_id][2](value)
    out["duration_seconds"] = round(time.time() - t0, 3)
    db().execute("INSERT INTO findings (agent, subject, confidence, evidence, reasoning, source, next_action, created) VALUES (?,?,?,?,?,?,?,?)",
                 (agent_id, (value or out["task"])[:300], out["confidence"], json.dumps(out, default=str)[:20000],
                  out["task"], out["source"], out["recommended_action"], time.time()))
    db().commit()
    return out
