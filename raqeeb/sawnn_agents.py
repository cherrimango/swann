"""The sixteen SAWNN agents. Each one is a handler run by the orchestrator (raqeeb/orchestrator.py).

A handler receives the task input (a dict) and returns:
    findings            what the agent concluded (structured)
    evidence            what it based that on
    confidence          0-1, or None when the agent does not make a judgement
    sources             components or data the agent used
    recommended_action  next step for people
    handoffs            follow-up tasks for other agents: [(agent_id, input, input_refs)]
    errors              optional list of non-fatal problems

Agents analyse and recommend. None can approve threats, block globally or publish alerts. The discovery pipeline may
open a threat record with status "new" so analysts see it; everything after that stays with people.
"""
import json
import os
import re
import time

from . import agents as core
from .db import db, rows

UAE_BRAND_HINT = re.compile(r"uae|emirat|dubai|abudhabi|abu-dhabi|sharjah|tamm|uaepass|icp|gdrfa|salik|darb|rta|adcb|enbd|fab|mashreq|"
                            r"etisalat|aramex|emiratespost|mohre|adpolice|dubaipolice|ajman|fujairah|\.ae\b", re.I)


def _scan(url, mode="quick", skip=()):
    from .link import pipeline
    r = pipeline.analyse(url, mode, skip_sources=skip)
    pipeline.save(r, None)
    return r


def _conf(level):
    return {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}.get(level)


# 1
def global_threat_hunter(inp):
    """Batch of discovered indicators → one URL Analysis task each. Look-alike sweep mode checks DNS for brand permutations."""
    if inp.get("mode") == "lookalikes":
        from . import hunt
        from .brands import BRANDS
        found, errors = [], []
        if os.environ.get("SAWNN_HUNT_DNS", "1") == "0":
            return {"findings": {"skipped": "SAWNN_HUNT_DNS=0"}, "sources": [], "confidence": None}
        for b in BRANDS[:12]:
            for d in hunt.candidates(b, 15):
                try:
                    if hunt.resolves(d):
                        found.append(d)
                except Exception as e:  # noqa: BLE001
                    errors.append(str(e)[:80])
                    break
            if len(errors) > 3:
                break
        return {"findings": {"resolving_lookalikes": found[:50]}, "evidence": {"brands_checked": min(12, len(BRANDS))},
                "sources": ["DNS (system resolver)", "SAWNN brand registry"], "confidence": None, "errors": errors[:3],
                "recommended_action": "Review resolving look-alikes in Link & domain analysis." if found else "",
                "handoffs": [("url_analysis", {"url": "http://" + d, "origin": "lookalike_sweep"}, [f"domain:{d}"]) for d in found[:20]]}
    items = inp.get("indicators", [])
    by_src = {}
    for i in items:
        by_src[i["source"]] = by_src.get(i["source"], 0) + 1
    return {"findings": {"indicators_received": len(items), "by_source": by_src}, "evidence": {"sample": [i["value"] for i in items[:10]]},
            "sources": ["SAWNN Global Threat Discovery Engine"], "confidence": None,
            "recommended_action": "Automatic: each indicator gets its own analysis workflow before any analyst sees it."}


# 2
def url_analysis(inp):
    """Static URL/domain analysis (PSL parsing, structural flags, model score)."""
    from .link import ml, static_analyzer, url_validator
    v = url_validator.validate(inp["url"])
    flags = [k for k, x in v["flags"].items() if x]
    m = ml.predict(v["normalised_url"])
    out = {"findings": {"registered_domain": v["registered_domain"], "flags": flags,
                        "model": {"prediction": m.get("prediction"), "probability": m.get("probability")}},
           "evidence": {"features": static_analyzer.url_features(v)}, "sources": ["URL validator (offline PSL)", "SAWNN URL model"],
           "confidence": m.get("probability") if m.get("available") else None,
           "handoffs": [("phishing_intelligence", {**inp, "normalised_url": v["normalised_url"]}, [f"url:{v['normalised_url']}"])]}
    return out


# 3
def phishing_intelligence(inp):
    """Full quick scan through the shared Link Intelligence Engine; records the result on the discovery indicator."""
    # a discovered indicator is analysed independently of its own feed listing (no self-confirmation)
    r = _scan(inp.get("normalised_url") or inp["url"], skip=("sawnn_discovery",) if inp.get("indicator") else ())
    hand = []
    if r.get("detected_brand"):
        hand.append(("uae_brand_impersonation", {"url": r["normalised_url"], "scan_id": r["scan_id"]}, [f"scan:{r['scan_id']}"]))
    if r["verdict"] in ("MALICIOUS", "SUSPICIOUS") and os.environ.get("SAWNN_DISCOVERY_SANDBOX") == "1" and inp.get("feed"):
        hand.append(("sandbox_analysis", {"url": r["normalised_url"]}, [f"scan:{r['scan_id']}"]))
    if r["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
        hand.append(("campaign_correlation", {"trigger": r["scan_id"]}, [f"scan:{r['scan_id']}"]))
    threat_id = None
    if inp.get("indicator"):
        if r["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            from . import intel
            t, created = intel.upsert("url", inp["indicator"], "phishing", r.get("detected_brand") or "", r["risk_score"] or 0,
                                      (_conf(r["assessment_confidence"]) or 0.3), {"scan_id": r["scan_id"], "feed": inp.get("feed")},
                                      None, source=f"SAWNN Global Threat Discovery Engine ({inp.get('feed')})", status="new", actor="sawnn-agents")
            threat_id = t["id"]
            if created:
                from .orchestrator import _notify
                _notify("discovery_alert", {"threat_id": t["id"], "url": inp["indicator"][:300], "verdict": r["verdict"],
                                            "risk": r["risk_score"], "brand": r.get("detected_brand") or "", "feed": inp.get("feed")})
        db().execute("UPDATE indicators SET status='processed', verdict=?, risk=?, processed=?, threat_id=COALESCE(threat_id, ?) WHERE value=?",
                     (r["verdict"], r["risk_score"], time.time(), threat_id, inp["indicator"]))
    return {"findings": {"verdict": r["verdict"], "risk_score": r["risk_score"], "confidence": r["assessment_confidence"],
                         "scan_id": r["scan_id"], "threat_id": threat_id, "detected_brand": r.get("detected_brand")},
            "evidence": r["strongest_indicators"], "sources": ["SAWNN Link Intelligence Engine"] + r["signature_result"]["sources_checked"],
            "confidence": _conf(r["assessment_confidence"]), "recommended_action": r["recommended_action"]["en"], "handoffs": hand,
            "errors": list(r["signature_result"]["errors"].values())}


# 4
def uae_brand_impersonation(inp):
    from .brands import detect, official_brand
    from .urlparse import parse
    if not inp.get("url"):  # scheduled sweep over recently processed indicators
        recent = rows(db().execute("SELECT value FROM indicators WHERE processed > ? AND verdict IN ('MALICIOUS','SUSPICIOUS')", (time.time() - 3 * 3600,)))
        hits = []
        for r in recent:
            p = parse(r["value"])
            h = detect(p)
            if h and UAE_BRAND_HINT.search(p.url):
                hits.append({"url": r["value"], "brand": h[0].brand_name, "match": h[0].kind})
        return {"findings": {"uae_brand_hits": hits[:100], "checked": len(recent)}, "sources": ["SAWNN brand registry"], "confidence": None,
                "recommended_action": "Consider a citizen alert for brands with several hits." if len(hits) >= 3 else ""}
    p = parse(inp["url"])
    off = official_brand(p)
    hits = detect(p)
    return {"findings": {"official_domain_of": off["name"] if off else None,
                         "impersonates": [{"brand": h.brand_name, "match": h.kind, "matched": h.matched, "official": h.official} for h in hits]},
            "evidence": {"host": p.host, "registered_domain": p.registered_domain}, "sources": ["SAWNN brand registry"],
            "confidence": 0.85 if hits and hits[0].kind in ("host_keyword", "homoglyph", "typosquat") else (0.5 if hits else None),
            "recommended_action": "Compare with the official site and verify in Threat verification." if hits else ""}


# 5
def sandbox_analysis(inp):
    r = _scan(inp["url"], "deep")
    sb = r.get("website_analysis") or {}
    hand = [("visual_impersonation", {"scan_id": r["scan_id"]}, [f"scan:{r['scan_id']}"])] if sb.get("screenshot") else []
    return {"findings": {"verdict": r["verdict"], "analysis_status": r.get("analysis_status"), "final_url": r.get("final_url"),
                         "password_fields": sb.get("password_fields"), "payment_fields": sb.get("payment_fields")},
            "evidence": {"redirects": r.get("redirects")}, "sources": [sb.get("mode") or "sandbox unavailable"],
            "confidence": _conf(r["assessment_confidence"]), "recommended_action": r["recommended_action"]["en"], "handoffs": hand,
            "errors": [] if sb.get("available") else [sb.get("error") or sb.get("browser_error") or "sandbox unavailable"]}


# 6
def visual_impersonation(inp):
    from .link import pipeline
    r = pipeline.get(inp.get("scan_id", "")) or {}
    vis = r.get("visual_analysis") or {}
    return {"findings": {k: vis.get(k) for k in ("detected_brand", "overall_visual_similarity", "closest_reference")},
            "evidence": {"indicators": vis.get("indicators")}, "sources": ["pHash + layout + colour + OCR"],
            "confidence": vis.get("overall_visual_similarity"), "errors": [] if vis.get("available") else [vis.get("reason") or "no visual result"],
            "recommended_action": "Visual similarity alone is not proof; confirm with domain and form evidence."}


# 7
def message_intelligence(inp):
    m = core.check_message(inp["text"])
    hand = [("sentiment_social_engineering", {"text": inp["text"]}, inp.get("refs", []))]
    for link in m["links"][:5]:
        hand.append(("url_analysis", {"url": link["url"], "origin": inp.get("report_ref")}, [f"url:{link['url']}"]))
    for ph in sorted({x for x in re.findall(r"(?:\+|00)?971[\d\s-]{8,12}", inp["text"])})[:3]:
        hand.append(("phone_intelligence", {"number": ph}, [f"phone:{ph}"]))
    return {"findings": {"verdict": m["verdict"], "risk_score": m["risk_score"], "script_signals": [s["code"] for s in m["script_signals"]],
                         "brands_named": m["brands_named"]},
            "evidence": {"script_signals": m["script_signals"]}, "sources": ["SAWNN message rules (EN/AR)"],
            "confidence": round(m["risk_score"] / 100, 2), "recommended_action": m["advice_en"], "handoffs": hand}


# 8
def advertisement_intelligence(inp):
    m = core.check_message(inp["text"])
    out, f = core.ad_agent(inp["text"], m.get("links", []))
    return {"findings": out, "evidence": f.evidence, "sources": ["SAWNN advert rules"], "confidence": f.confidence,
            "recommended_action": f.next_action or "Report the advert to the platform.",
            "handoffs": [("sentiment_social_engineering", {"text": inp["text"]}, [])]}


# 9
def phone_intelligence(inp):
    out, f = core.phone_agent(inp["number"])
    return {"findings": out, "evidence": f.evidence, "sources": ["SAWNN threat records", "citizen reports"], "confidence": f.confidence,
            "recommended_action": f.next_action or "No action unless analysts confirm the number."}


# 10
def qr_intelligence(inp):
    payload = inp.get("payload", "")
    if payload.lower().startswith(("http://", "https://", "www.")):
        return {"findings": {"payload_type": "url"}, "sources": ["QR decoder"], "confidence": None,
                "handoffs": [("url_analysis", {"url": payload, "origin": "qr"}, [f"url:{payload}"])]}
    kind = "payment" if payload.lower().startswith(("upi:", "bitcoin:", "ethereum:")) else "wifi" if payload.startswith("WIFI:") else "text"
    return {"findings": {"payload_type": kind}, "evidence": {"payload": payload[:300]}, "sources": ["QR decoder"], "confidence": None,
            "recommended_action": "Never pay or join networks from a QR code you did not expect."}


# 11
def campaign_correlation(inp):
    g = core.correlate()
    camps = g.get("campaigns", []) if isinstance(g, dict) else []
    return {"findings": {"campaigns": len(camps), "largest": [{"id": c.get("id"), "threats": len(c.get("threats", []))} for c in
                                                             sorted(camps, key=lambda c: -len(c.get("threats", [])))[:5]]},
            "sources": ["SAWNN threat records"], "confidence": None, "recommended_action": "Investigate the largest new campaigns first.",
            "handoffs": [("briefing", {"period": "day"}, [])] if inp.get("trigger") == "schedule_brief" else []}


# 12
def seasonal(inp):
    s = core.seasonal_agent()
    return {"findings": {"active": s.get("active_seasons") or [p.get("season") for p in s.get("predicted", [])][:5]},
            "evidence": s, "sources": ["seasonal calendar", "observed signals"], "confidence": None,
            "recommended_action": "Prepare citizen alerts for active seasons. Predictions are not confirmed incidents."}


# 13
def community(inp):
    q = rows(db().execute("SELECT status, COUNT(*) n FROM citizen_reports GROUP BY status"))
    return {"findings": {"reports_by_status": {r["status"]: r["n"] for r in q}}, "sources": ["SAWNN Protect reports"], "confidence": None,
            "recommended_action": "Review reports waiting in the queue. Reports alone never trigger blocks."}


# 14
def sentiment_social_engineering(inp):
    from .sentiment import analyse
    se = analyse(inp["text"])
    return {"findings": {k: se[k] for k in ("language", "sentiment", "manipulation_score", "pressure_with_action", "confidence")},
            "evidence": {"indicators": se["indicators"]}, "sources": ["SAWNN social-engineering lexicon (EN/AR)"],
            "confidence": se["manipulation_score"], "recommended_action": se["explanation_en"]}


# 15
def briefing(inp):
    b = core.briefing_agent(inp.get("period", "day"))
    return {"findings": b, "sources": ["SAWNN records"], "confidence": None, "recommended_action": "Share with the duty officer."}


# 16
def protection_distribution(inp):
    d = core.distribution_agent()
    return {"findings": {"ready_for_approval": len(d)}, "evidence": {"threats": d[:30]}, "sources": ["SAWNN threat records"], "confidence": None,
            "recommended_action": "Open Blocking & distribution to approve. Agents never publish protection."}


AGENTS = {
    "global_threat_hunter": ("Global Threat Hunter", None, global_threat_hunter),
    "phishing_intelligence": ("Phishing Intelligence", "url", phishing_intelligence),
    "url_analysis": ("URL Analysis", "url", url_analysis),
    "uae_brand_impersonation": ("UAE Brand Impersonation", "url", uae_brand_impersonation),
    "sandbox_analysis": ("Sandbox Analysis", "url", sandbox_analysis),
    "visual_impersonation": ("Visual Impersonation", "scan_id", visual_impersonation),
    "message_intelligence": ("Message Intelligence", "text", message_intelligence),
    "advertisement_intelligence": ("Advertisement Intelligence", "text", advertisement_intelligence),
    "phone_intelligence": ("Phone Intelligence", "number", phone_intelligence),
    "qr_intelligence": ("QR Intelligence", "payload", qr_intelligence),
    "campaign_correlation": ("Campaign Correlation", None, campaign_correlation),
    "seasonal": ("Seasonal Threat", None, seasonal),
    "community": ("Community Intelligence", None, community),
    "sentiment_social_engineering": ("Sentiment & Social Engineering", "text", sentiment_social_engineering),
    "briefing": ("Intelligence Briefing", "period", briefing),
    "protection_distribution": ("Protection Distribution", None, protection_distribution),
}
AGENT_HANDLERS = {k: v[2] for k, v in AGENTS.items()}


def catalogue():
    return [{"id": k, "name": n, "input": i} for k, (n, i, _) in AGENTS.items()]


def run(agent_id: str, value: str | None = None) -> dict:
    """Run one agent through the orchestrator (with its hand-offs) and return the workflow with every task."""
    from . import orchestrator
    if agent_id not in AGENTS:
        raise KeyError(agent_id)
    field = AGENTS[agent_id][1]
    payload = {field: value} if field and value else {}
    if agent_id == "briefing" and not value:
        payload = {"period": "day"}
    return orchestrator.run_sync("manual", payload, "analyst request", agent_id)


_ = json
