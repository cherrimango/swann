"""Runs the Link Intelligence Engine stages in order and builds the standard scan report.

quick mode: validation, static URL analysis, registry, offline signatures, rules, ML  (about 10 ms, no network)
deep mode:  adds external signature APIs, RDAP / DNS / certificate, the browser sandbox and visual analysis
Partial results are kept when optional stages fail.
"""
import datetime as dt
import json
import secrets
import time

from ..db import ROOT, db, one
from ..engine import scan as core_scan
from . import ml, official_domains, risk, signatures, static_analyzer, url_validator
from .url_validator import InvalidURL  # noqa: F401  (re-exported for the API layer)

ENGINE_VERSION = "raqeeb-link-1.0"
SHOTS = ROOT / "evidence" / "scans"

ACTIONS = {
    "MALICIOUS": ("Do not open it or enter any details. Report it and block it.", "لا تفتحه ولا تُدخل أي بيانات. أبلغ عنه واحظره."),
    "SUSPICIOUS": ("Don't enter details. Open the service from its official app or a domain you type yourself.",
                   "لا تُدخل بياناتك. افتح الخدمة من تطبيقها الرسمي أو من عنوان تكتبه بنفسك."),
    "INCONCLUSIVE": ("Not enough evidence either way. Treat it with caution, or run a deep scan.",
                     "لا توجد أدلة كافية. تعامل معه بحذر أو شغّل فحصاً معمّقاً."),
    "SAFE": ("No significant malicious indicators. Still log in and pay only through official apps.",
             "لا توجد مؤشرات خطر واضحة. ومع ذلك سجّل الدخول وادفع عبر التطبيقات الرسمية فقط."),
}


def new_id() -> str:
    return f"SCAN-{dt.datetime.now(dt.timezone.utc):%Y%m%d}-{secrets.token_hex(3).upper()}"


def analyse(url: str, mode: str = "quick", scan_id: str | None = None) -> dict:
    t0 = time.time()
    scan_id = scan_id or new_id()
    v = url_validator.validate(url)
    stages = {"validation": "complete"}
    static = static_analyzer.url_features(v)
    stages["static"] = "complete"
    reg = official_domains.match(v)
    stages["registry"] = "complete"
    deep = mode == "deep"
    sig = signatures.check(v, external=deep)
    stages["signatures"] = "complete" if not sig["errors"] else "partial"
    core = core_scan(v["normalised_url"])
    m = ml.predict(v["normalised_url"])
    stages["ml"] = "complete" if m["available"] else "unavailable"
    r = {"validation": v, "core": core, "registry": reg, "signatures": sig, "ml": m, "stages": stages}

    domain = sandbox = visual = None
    if deep:
        from . import sandbox as sandbox_mod
        from . import visual as visual_mod
        domain = static_analyzer.domain_features(v)
        stages["domain"] = "complete" if all(domain[k].get("available") for k in ("rdap", "dns", "certificate")) else \
            "partial" if any(domain[k].get("available") for k in ("rdap", "dns", "certificate")) else "unavailable"
        shot = SHOTS / f"{scan_id}.png"
        sandbox = sandbox_mod.analyse(v["normalised_url"], shot)
        stages["sandbox"] = ("complete" if sandbox.get("mode") == "headless browser" else "partial") if sandbox.get("available") else "unavailable"
        if sandbox.get("available") and sandbox.get("final_url"):
            fv = url_validator.validate(sandbox["final_url"])
            if fv["registered_domain"] != v["registered_domain"]:
                r["final_core"] = core_scan(fv["normalised_url"])
        visual = visual_mod.analyse(shot if sandbox.get("screenshot") else None,
                                    (sandbox.get("page_title") or "") + " " + (sandbox.get("visible_text") or ""))
        stages["visual"] = "complete" if visual["available"] else "partial" if visual["brand_text_found"] or visual["ocr"].get("available") else "unavailable"
    else:
        for s in ("domain", "sandbox", "visual"):
            stages[s] = "not_run"
    r.update({"domain": domain, "sandbox": sandbox, "visual": visual})
    agg = risk.aggregate(r)

    brand = core.get("impersonated_brand")
    detected = brand["name"] if brand else reg["organisation"] if reg["official_domain_match"] else (
        (visual or {}).get("detected_brand") or ((visual or {}).get("brand_text_found") or [None])[0])
    limitations = agg["limitations"] + ([] if deep else ["Quick scan: domain registration, DNS, certificate, live page and "
                                                         "visual checks were not run. Use mode=deep for the full pipeline."])
    if deep and sandbox and not sandbox.get("available"):
        limitations.append(f"Live page analysis unavailable: {sandbox.get('error') or sandbox.get('browser_error')}")
    if visual and not visual["available"]:
        limitations.append(f"Visual comparison unavailable: {visual.get('reason')}")
    strongest = [e for e in agg["evidence"] if e["direction"] == "risk"][:3]
    en_why = "; ".join(e["detail_en"] for e in strongest) or "No significant risk indicators."
    ar_why = "؛ ".join(e["detail_ar"] for e in strongest) or "لا توجد مؤشرات خطر واضحة."
    return {
        "scan_id": scan_id, "engine_version": ENGINE_VERSION, "mode": mode, "submitted_url": url,
        "normalised_url": v["normalised_url"], "final_url": (sandbox or {}).get("final_url"),
        "registered_domain": v["registered_domain"], "verdict": agg["verdict"], "risk_score": agg["risk_score"],
        "risk_level": agg["risk_level"], "assessment_confidence": agg["assessment_confidence"],
        "analysis_completeness": agg["analysis_completeness"], "detected_brand": detected,
        "official_domain_match": reg["official_domain_match"], "official_domain_comparison": reg,
        "twin_view": (brand or {}).get("twin"),
        "ml_result": m, "signature_result": sig,
        "static_analysis": {"validation": {k: v[k] for k in ("scheme", "hostname", "hostname_unicode", "subdomain", "tld", "path",
                                                              "query_parameters", "fragment", "url_length", "flags")}, "features": static},
        "domain_intelligence": domain or {"available": False, "reason": "not run in quick mode"},
        "website_analysis": sandbox or {"available": False, "reason": "not run in quick mode"},
        "visual_analysis": visual or {"available": False, "reason": "not run in quick mode"},
        "evidence": agg["evidence"], "strongest_indicators": strongest,
        "explanation": {"en": en_why, "ar": ar_why},
        "recommended_action": {"en": ACTIONS[agg["verdict"]][0], "ar": ACTIONS[agg["verdict"]][1]},
        "stages": stages, "limitations": limitations, "duration_seconds": round(time.time() - t0, 3),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }


def save(report: dict, user_id: int | None, status: str = "complete"):
    db().execute("""INSERT INTO scans (id, url, verdict, risk_score, mode, status, report, user_id, created) VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET verdict=excluded.verdict, risk_score=excluded.risk_score, status=excluded.status, report=excluded.report""",
                 (report["scan_id"], report.get("submitted_url", "")[:2000], report.get("verdict"), report.get("risk_score"),
                  report.get("mode", "quick"), status, json.dumps(report, default=str), user_id, time.time()))


def get(scan_id: str) -> dict | None:
    r = one(db().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)))
    if not r:
        return None
    rep = json.loads(r["report"])
    rep["status"], rep["owner"] = r["status"], r["user_id"]
    return rep
