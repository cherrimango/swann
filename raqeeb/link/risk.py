"""Risk aggregation: turns stage results into one verdict with three separate measurements:

  risk_score             0-100, how dangerous the evidence says the link is (not a probability)
  assessment_confidence  LOW / MEDIUM / HIGH, how much the evidence agrees and how reliable it is
  analysis_completeness  0-1, how much of the pipeline actually ran

Rules: strong, reliable evidence (a confirmed signature, an official domain, a credential page impersonating a brand)
sets floors and caps; weak indicators (young domain, certificate problems) can raise a score but never push a link
over the HIGH boundary on their own; a stage that failed lowers completeness and confidence, never the score.
"""
import os

LEVELS = [int(x) for x in os.environ.get("SAWNN_RISK_LEVELS", "25,50,75").split(",")]
STAGE_WEIGHTS = {"validation": 0.05, "static": 0.10, "registry": 0.10, "signatures": 0.15, "ml": 0.15,
                 "domain": 0.15, "sandbox": 0.20, "visual": 0.10}


def level(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    low, mod, high = LEVELS
    return "LOW" if score < low else "MODERATE" if score < mod else "HIGH" if score < high else "CRITICAL"


SOURCE_NAMES = {"raqeeb_published": "SAWNN's published protection list", "raqeeb_threats": "SAWNN's verified threat records",
                "public_feeds": "public phishing feeds (OpenPhish / Phishing.Database)", "google_web_risk": "Google Web Risk",
                "virustotal": "VirusTotal", "urlhaus": "URLhaus",
                "sawnn_discovery": "SAWNN Threat Discovery Engine (feed indicator)"}


def ev(stage, signal, en, ar, direction, strength, reliability):
    return {"stage": stage, "signal": signal, "detail_en": en, "detail_ar": ar, "direction": direction,
            "strength": round(strength, 2), "reliability": reliability}


def aggregate(r: dict) -> dict:
    """r holds the stage outputs from pipeline.analyse. Returns score, level, verdict, confidence, completeness, evidence."""
    core, reg, sig, ml, stages = r["core"], r["registry"], r["signatures"], r["ml"], r["stages"]
    evidence, limitations = [], []
    score = float(core["risk_score"])
    strong = 0

    for x in core["reasons"]:
        if x["code"] in ("official_domain", "popular_domain", "regional_brand", "restricted_registry"):
            evidence.append(ev("registry", x["code"], x["en"], x["ar"], "trust", 0.9 if x["code"] == "official_domain" else 0.5, "high"))
        elif not x["code"].startswith("ml:") and x["code"] != "threat_feed":
            st = min(1.0, x["weight"] / 3)
            evidence.append(ev("static" if x["code"] in ("lure_words", "shortener", "punycode", "ip_with_lures") else "brand",
                               x["code"], x["en"], x["ar"], "risk", st, "medium"))
            strong += st >= 0.8

    fl = r["validation"]["flags"]
    if fl.get("rtl_override"):
        evidence.append(ev("static", "rtl_override", "Link contains a right-to-left override character, a trick used to disguise addresses",
                           "يحتوي الرابط على محرف عكس الاتجاه، وهي حيلة لإخفاء العنوان الحقيقي", "risk", 0.6, "high"))
        score = max(score, 45.0)
    if sig["matches"]:
        for m in sig["matches"]:
            name = SOURCE_NAMES.get(m["source"], m["source"])
            evidence.append(ev("signatures", m["source"], f"Listed as {m['classification']} in {name}"
                               + (f" ({m['reference']})" if m.get("reference") else ""),
                               "مدرج كتهديد في " + ("قائمة الحماية المنشورة في صون" if m["source"] == "raqeeb_published" else
                                                    "سجلات التهديدات الموثّقة في صون" if m["source"] == "raqeeb_threats" else name),
                               "risk", 1.0, "high"))
        strong_matches = [m for m in sig["matches"] if m["source"] != "sawnn_discovery"]
        if strong_matches:
            score = max(score, 97.0 if any(m["source"].startswith("raqeeb") for m in strong_matches) else 95.0)
            strong += 2
        else:  # only an unverified feed indicator from the discovery engine: a lead, not proof
            score = max(score, 60.0)
            strong += 1

    if ml["available"]:
        agree = (ml["prediction"] == "phishing") == (score >= 50)
        evidence.append(ev("ml", "model", f"URL model: {ml['prediction']} (score {ml['probability']:.2f}, threshold {ml['decision_threshold']:.2f})",
                           f"نموذج الروابط: {'تصيد' if ml['prediction'] == 'phishing' else 'مشروع'}",
                           "risk" if ml["prediction"] == "phishing" else "trust", abs(ml["probability"] - 0.5) * 2, "medium"))
        if not agree:
            limitations.append("The URL model and the rule layer disagree; review the evidence before acting.")
    else:
        limitations.append("Machine-learning classification unavailable.")

    d = r.get("domain") or {}
    rdap = d.get("rdap", {})
    if rdap.get("available") and rdap.get("age_days") is not None and not reg["official_domain_match"]:
        age = rdap["age_days"]
        if age < 30:
            evidence.append(ev("domain", "young_domain", f"Domain registered {age} days ago", f"النطاق مسجّل منذ {age} يوماً",
                               "risk", 0.4, "high"))
            score = max(score, min(score + 8, 49.0)) if score < 50 else min(100.0, score + 5)
        elif age > 3 * 365:
            evidence.append(ev("domain", "old_domain", f"Domain registered {age // 365} years ago", "نطاق قديم التسجيل", "trust", 0.2, "high"))
    if d.get("dns", {}).get("nxdomain"):
        limitations.append("The domain does not resolve (taken down, parked or not yet live); judged from the link alone.")
    cert = d.get("certificate", {})
    if cert.get("available") and cert.get("valid") is False:
        evidence.append(ev("domain", "invalid_certificate", f"TLS certificate invalid: {cert.get('validation_error')}",
                           "شهادة TLS غير صالحة", "risk", 0.3, "high"))
        score = max(score, min(score + 5, 49.0)) if score < 50 else score

    sb = r.get("sandbox") or {}
    if sb.get("available"):
        page_brands = (r.get("visual") or {}).get("brand_text_found") or []
        sensitive = sb.get("password_fields", 0) > 0 or sb.get("payment_fields")
        if page_brands and sensitive and not reg["official_domain_match"]:
            what = "payment" if sb.get("payment_fields") else "password"
            evidence.append(ev("sandbox", "brand_credential_page",
                               f"Page uses {', '.join(page_brands)} branding and asks for {what} details on a non-official domain",
                               f"الصفحة تستخدم علامة {', '.join(page_brands)} وتطلب بيانات حساسة على نطاق غير رسمي", "risk", 1.0, "high"))
            score = max(score, 90.0)
            strong += 2
        elif sensitive and not reg["official_domain_match"]:
            evidence.append(ev("sandbox", "sensitive_form", "Page asks for a password or payment details",
                               "الصفحة تطلب كلمة مرور أو بيانات دفع", "risk", 0.4, "medium"))
        ext = [f["action"] for f in sb.get("forms", []) if f["external"]]
        if ext and sensitive:
            evidence.append(ev("sandbox", "external_form", f"Form sends data to another site: {ext[0][:80]}",
                               "النموذج يرسل البيانات إلى موقع آخر", "risk", 0.6, "high"))
            score = min(100.0, score + 10)
        if sb.get("downloads_blocked"):
            evidence.append(ev("sandbox", "download", f"Page tried to download a file: {sb['downloads_blocked'][0]}",
                               "حاولت الصفحة تنزيل ملف", "risk", 0.6, "high"))
            score = min(100.0, score + 10)
        if r.get("final_core") and r["final_core"]["risk_score"] > score:
            fc = r["final_core"]
            evidence.append(ev("sandbox", "redirect_destination", f"Redirects to a riskier destination: {fc['host']}",
                               f"يعيد التوجيه إلى وجهة أخطر: {fc['host']}", "risk", 0.8, "high"))
            score = fc["risk_score"]
            strong += 1
    vis = r.get("visual") or {}
    if vis.get("available") and (vis.get("overall_visual_similarity") or 0) >= 0.6 and not reg["official_domain_match"]:
        evidence.append(ev("visual", "visual_clone", vis["indicators"][0], "الصفحة تشبه الصفحة الرسمية", "risk", 0.7, "medium"))
        score = max(score, 85.0)
        strong += 1

    if reg["official_domain_match"] and not sig["matches"]:
        score = min(score, 5.0)
    score = round(max(0.0, min(100.0, score)), 1)

    completeness = 0.0
    for name, w in STAGE_WEIGHTS.items():
        s = stages.get(name, "not_run")
        completeness += w * (1.0 if s == "complete" else 0.5 if s == "partial" else 0.0)
    completeness = round(completeness, 2)

    official = reg["official_domain_match"]
    strong_sig = any(m["source"] != "sawnn_discovery" for m in sig["matches"])
    if strong_sig or official:
        confidence = "HIGH"
    elif score >= 75:
        confidence = "HIGH" if strong >= 2 or (ml["available"] and ml["prediction"] == "phishing") else "MEDIUM"
    elif score < 25:
        confidence = "MEDIUM" if ml["available"] and completeness >= 0.5 else "LOW"
    else:
        confidence = "MEDIUM" if strong >= 1 or (ml["available"] and (ml["prediction"] == "phishing") == (score >= 50)) else "LOW"
    if completeness < 0.4 and confidence == "HIGH" and not (strong_sig or official):
        confidence = "MEDIUM"

    lvl = level(score)
    shortener_unresolved = r["validation"]["flags"]["shortener"] and not (sb.get("available") and sb.get("final_url"))
    if any(m["source"] != "sawnn_discovery" for m in sig["matches"]) or lvl == "CRITICAL":
        verdict = "MALICIOUS"
    elif lvl == "HIGH":
        verdict = "SUSPICIOUS"
    elif shortener_unresolved:
        verdict = "INCONCLUSIVE"
        limitations.append("Shortened link: the real destination is hidden. Run a deep scan to follow it.")
    elif lvl == "MODERATE":
        verdict = "SUSPICIOUS" if confidence != "LOW" else "INCONCLUSIVE"
    else:
        # SAWNN rule: SAFE needs positive evidence, never just the absence of warnings. HTTPS, a valid certificate, an old
        # domain, no threat-feed listing or a failed sandbox are not enough. Accepted grounds: an official registry match,
        # a well-established domain with a benign model result, or a deep scan whose live-page analysis completed.
        benign_ml = ml["available"] and ml["prediction"] != "phishing"
        popular = any(e["signal"] in ("popular_domain", "regional_brand", "restricted_registry") for e in evidence)
        deep_ok = stages.get("sandbox") == "complete" and stages.get("domain") in ("complete", "partial") and completeness >= 0.75
        if official or (benign_ml and (popular or deep_ok)):
            verdict = "SAFE"
        else:
            verdict = "INCONCLUSIVE"
            why = ("the live page could not be analysed" if stages.get("sandbox") in ("unavailable", "failed") else
                   "only the link itself was analysed" if stages.get("sandbox") == "not_run" else "the evidence is incomplete")
            limitations.append(f"No malicious indicators were found, but SAWNN cannot call this site safe: {why}, and the domain is "
                               "neither official nor well established. Treat it with care.")
    if verdict == "SAFE":
        limitations.append("SAFE means no significant malicious indicators were found, not a guarantee.")

    evidence.sort(key=lambda e: (e["direction"] != "risk", -e["strength"]))
    return {"risk_score": score, "risk_level": lvl, "verdict": verdict, "assessment_confidence": confidence,
            "analysis_completeness": completeness, "evidence": evidence, "limitations": limitations}
