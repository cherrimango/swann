"""SAWNN scoring engine: allowlist + brand impersonation rules + ML model -> risk score with reasons (EN/AR)."""
import gzip
import os
from pathlib import Path

import numpy as np

from .brands import SCAM_TYPES, detect, official_brand
from .features import READABLE
from .model import Model
from .twin import twin
from .urlparse import FREE_HOSTING, SHORTENERS, lure_tokens, parse, under_any

TOP_LEGIT = set((Path(__file__).parent / "data" / "top_legit_10k.txt").read_text().split())
# Brand labels of top sites ("amazon" from amazon.com): the exact label on a country-code TLD is
# almost always that brand's own regional site (amazon.ae, ikea.ae), not an impersonation.
TOP_LABELS = {d.split(".")[0] for d in TOP_LEGIT if len(d.split(".")[0]) >= 4}

READABLE_AR = {
    "free_hosting": "نطاق فرعي على استضافة مجانية أو أداة إنشاء مواقع",
    "tld_risky": "امتداد نطاق شائع الاستخدام في الاحتيال",
    "host_entropy": "اسم نطاق عشوائي المظهر", "host_hyphens": "شرطات كثيرة في اسم النطاق",
    "host_digits": "أرقام في اسم النطاق", "subdomain_depth": "سلسلة نطاقات فرعية عميقة",
    "host_len": "اسم نطاق طويل جداً", "longest_label": "جزء طويل جداً في اسم النطاق",
    "is_ip": "عنوان IP بدلاً من اسم نطاق", "is_punycode": "أحرف مشابهة أو بيونيكود",
    "lure_words_host": "كلمات استدراج في اسم النطاق", "lure_words_path": "كلمات استدراج في مسار الرابط",
    "lr_prob": "نمط أحرف مشابه لروابط تصيد معروفة", "domain_hyphens": "نطاق يحتوي على شرطات",
    "digit_letter_mix": "خلط الحروف بالأرقام", "consonant_run": "سلسلة أحرف عشوائية",
    "has_at": "خدعة '@' في الرابط", "embedded_url": "رابط آخر مضمّن داخل الرابط",
    "shortener": "رابط مختصر يخفي الوجهة", "url_len": "رابط طويل جداً",
}

# Popular registered domains where anyone can publish pages or files. Popularity of the domain says nothing about the
# page, so these never receive the popular-domain cap (Google Docs/Sites/Forms, SharePoint, Dropbox, cloud storage...).
USER_CONTENT_HOSTS = {
    "docs.google.com", "sites.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "script.google.com", "googleusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com", "dropbox.com",
    "dl.dropboxusercontent.com", "blob.core.windows.net", "web.core.windows.net", "github.io", "gitlab.io", "notion.site",
    "linktr.ee", "t.me", "telegra.ph", "medium.com", "wordpress.com", "blogspot.com", "box.com", "wetransfer.com",
    "mediafire.com", "s3.amazonaws.com", "cloudfront.net", "workers.dev", "pages.dev", "web.app", "firebaseapp.com",
    "translate.goog", "ipfs.io", "adnxs.com", "doubleclick.net", "app.link", "page.link", "typeform.com", "jotform.com",
    "forms.office.com", "forms.microsoft.com", "wpengine.com", "inmotionhosting.com", "secureserver.net", "myftpupload.com",
    "esy.es", "hol.es", "16mb.com", "pe.hu", "hostingersite.com", "altervista.org", "webcindario.com", "weebly.com",
    "wixsite.com", "wix.com", "yolasite.com", "godaddysites.com", "000webhostapp.com", "squarespace.com", "webflow.io",
}


# .ae restricted zones: registration requires documents proving the entity is a government body, the armed forces, an
# accredited academic institution or a school (.aeDA Domain Name Eligibility Policy AEDA-POL-007, sections 14-16).
RESTRICTED_ZONES = {"gov.ae", "mil.ae", "ac.ae", "sch.ae"}


def user_content(p) -> bool:
    h = p.host.removeprefix("www.")
    return (any(h == d or h.endswith("." + d) for d in USER_CONTENT_HOSTS) or p.registered_domain in USER_CONTENT_HOSTS
            or p.registered_domain.startswith("blogspot."))


_model = None
_threat = None
MODELS = Path(os.environ.get("SAWNN_MODEL_PATH") or Path(__file__).resolve().parent.parent / "models")


def threat_lists():
    """Hosts and exact URLs from public phishing feeds (rebuilt by data/download.py)."""
    global _threat
    if _threat is None:
        def load(name):
            f = MODELS / name
            return set(gzip.open(f, "rt").read().split()) if f.exists() else set()
        _threat = (load("threat_hosts.txt.gz"), load("threat_urls.txt.gz"))
    return _threat


def model() -> Model:
    global _model
    if _model is None:
        _model = Model.load()
    return _model


def calibrate(prob: float, thr: float) -> float:
    """Map model probability to 0-100 so the decision threshold sits at exactly 50."""
    if prob < thr:
        return 50.0 * prob / thr
    return 50.0 + 50.0 * (prob - thr) / max(1e-9, 1.0 - thr)


def _reason(code, en, ar, weight):
    return {"code": code, "en": en, "ar": ar, "weight": round(float(weight), 3)}


def scan_many(urls: list[str], use_threat_intel: bool = True) -> list[dict]:
    m = model()
    t_hosts, t_urls = threat_lists() if use_threat_intel else (set(), set())
    probs, contrib, _ = m.predict(urls)
    out = []
    for i, raw in enumerate(urls):
        p = parse(raw)
        prob = float(probs[i])
        risk = calibrate(prob, m.threshold)
        reasons, brand = [], None
        lures = sorted(lure_tokens(p.url))
        off = official_brand(p)
        hits = [] if off else detect(p)
        on_hosting = under_any(p.host, FREE_HOSTING)
        is_short = p.registered_domain in SHORTENERS or p.host in SHORTENERS
        ugc = user_content(p)
        model_flags = prob >= m.threshold
        # popular domains get the stricter operating point (validation FPR <= 0.1%) before their page is questioned
        model_flags_strict = prob >= m.meta.get("threshold_strict", m.threshold)
        restricted = p.suffix in RESTRICTED_ZONES and not ugc
        has_path = bool((p.path or "").strip("/") or p.query)
        top_legit = p.registered_domain in TOP_LEGIT and not on_hosting and not is_short and not ugc
        cc = p.suffix.split(".")[-1] if p.suffix else ""
        regional_brand = (not top_legit and not on_hosting and not ugc and len(cc) == 2 and p.domain in TOP_LABELS
                          and not p.subdomain.replace("www", "").strip(".") and not lure_tokens(p.url))
        if top_legit:  # a brand word in a search query or article path on a major site is not impersonation
            hits = [h for h in hits if not (h.kind == "path_keyword" and h.strength < 0.8)]

        if off:
            risk = min(risk, 5.0)
            reasons.append(_reason("official_domain", f"Official {off['name']} domain",
                                   f"نطاق رسمي لـ {off['name_ar']}", -1))
        elif top_legit and not hits and not (model_flags_strict and has_path):
            risk = min(risk, 20.0)
            reasons.append(_reason("popular_domain", "Well-established popular domain",
                                   "نطاق معروف وواسع الاستخدام", -0.5))
        elif top_legit and not hits:
            # A popular domain does not make every page on it safe: hacked sites and open redirects host phishing.
            risk = min(max(risk, 40.0), 49.0)
            reasons.append(_reason("popular_domain_risky_path", "Popular domain, but this page's address looks like known phishing pages "
                                   "(possible compromised page or open redirect)", "نطاق معروف لكن مسار الصفحة يشبه صفحات تصيد معروفة", 1))
        elif restricted and not hits and not (lures and model_flags):
            risk = min(risk, 25.0)
            reasons.append(_reason("restricted_registry", f"Registered in the restricted .{p.suffix} zone, which requires proof of "
                                   "a government, academic or school entity", "مسجّل في نطاق إماراتي مقيّد يتطلب إثبات صفة الجهة", -0.4))
        elif regional_brand and not hits and not model_flags:
            risk = min(risk, 30.0)
            reasons.append(_reason("regional_brand", f"Regional site of a well-known brand ({p.domain}.{p.suffix})",
                                   "موقع إقليمي لعلامة تجارية معروفة", -0.4))
        else:
            if hits:
                h = hits[0]
                brand = {"id": h.brand_id, "name": h.brand_name, "name_ar": h.brand_name_ar,
                         "match": h.kind, "official_domains": h.official,
                         "likely_scams": [SCAM_TYPES[s] for s in h.scams if s in SCAM_TYPES],
                         "twin": twin(raw, h.official) if h.kind in ("host_keyword", "homoglyph", "typosquat") else None}
                off_str = ", ".join(h.official)
                if h.kind in ("host_keyword", "homoglyph"):
                    floor = 92 if (lures or on_hosting or p.suffix.split(".")[-1] not in ("ae",)) else 85
                    what = "look-alike characters of" if h.kind == "homoglyph" else "the name"
                    reasons.append(_reason("brand_impersonation",
                                           f"Uses {what} {h.brand_name} ('{h.matched}') but is not an official domain ({off_str})",
                                           f"يستخدم اسم {h.brand_name_ar} ('{h.matched}') لكنه ليس نطاقاً رسمياً ({off_str})", 3))
                elif h.kind == "typosquat":
                    floor = 85 if h.strength >= 0.9 else 45
                    reasons.append(_reason("typosquat", f"'{h.matched}' is a misspelling of {h.brand_name} ('{h.keyword}')",
                                           f"'{h.matched}' تهجئة خاطئة لاسم {h.brand_name_ar}", 2.5))
                elif h.kind == "path_keyword":
                    floor = (60 if top_legit else 80) if h.strength >= 0.8 else 45
                    reasons.append(_reason("brand_in_path", f"Mentions {h.brand_name} in the link path on an unrelated domain",
                                           f"يذكر {h.brand_name_ar} في مسار الرابط على نطاق غير تابع له", 2))
                else:
                    floor = 58 if (on_hosting or prob > 0.5) else risk
                    reasons.append(_reason("brand_token", f"Brand token '{h.matched}' ({h.brand_name}) combined with lure words",
                                           f"رمز العلامة '{h.matched}' مع كلمات استدراج", 1.5))
                if top_legit and h.kind != "path_keyword":
                    floor = min(floor, 60)
                risk = max(risk, floor)
            if ugc and (lures or model_flags):
                risk = max(risk, 45.0)
                reasons.append(_reason("user_content_host", "Hosted on a platform where anyone can publish pages or files "
                                       f"({p.registered_domain}); the domain's popularity says nothing about this page",
                                       "مستضاف على منصة يمكن لأي شخص النشر عليها؛ شهرة النطاق لا تعني أن الصفحة آمنة", 1.2))
            if p.is_ip and lures:
                risk = max(risk, 70)
                reasons.append(_reason("ip_with_lures", "Raw IP address with login/payment wording",
                                       "عنوان IP مع كلمات دخول أو دفع", 2))
            if is_short:
                risk = max(min(risk, 49), 40)
                reasons.append(_reason("shortener", "Shortened link hides the real destination; a deep scan or link preview can follow it",
                                       "رابط مختصر يخفي الوجهة الحقيقية", 1))
            if p.is_punycode and not hits:
                risk = max(risk, 55)
                reasons.append(_reason("punycode", "Internationalised (punycode) domain that can imitate other names",
                                       "نطاق دولي (بيونيكود) قد يقلّد أسماء أخرى", 1.5))

        if not off and (p.host.removeprefix("www.") in t_hosts or p.url.lower().rstrip("/") in t_urls):
            risk = max(risk, 97.0)
            reasons.append(_reason("threat_feed", "Already reported in public phishing threat feeds (OpenPhish / Phishing.Database)",
                                   "مُبلّغ عنه مسبقاً في قوائم التصيد العامة", 5))

        # Model explanation: top positive feature contributions.
        if not off and risk >= 35:
            c = contrib[i]
            for j in np.argsort(-c)[:3]:
                if c[j] > 0.25:
                    name = m.names[j]
                    reasons.append(_reason(f"ml:{name}", READABLE.get(name, name),
                                           READABLE_AR.get(name, "نمط مشبوه في الرابط"), c[j]))
        if lures and not off and risk >= 35:
            reasons.append(_reason("lure_words", "Lure words: " + ", ".join(lures[:6]),
                                   "كلمات استدراج: " + ", ".join(lures[:6]), 0.5))

        risk = float(np.clip(risk, 0, 100))
        trusted = bool(off) or any(r["code"] in ("popular_domain", "regional_brand", "restricted_registry") for r in reasons)
        # "safe" only for official or well-established domains; everything else low-risk is "inconclusive":
        # absence of warning signs in the address alone is not evidence of safety (SAWNN rule).
        verdict = "phishing" if risk >= 50 else ("suspicious" if risk >= 35 else ("safe" if trusted else "inconclusive"))
        out.append({
            "url": raw, "label": int(risk >= 50), "verdict": verdict, "risk_score": round(risk, 1),
            "model_probability": round(prob, 4), "host": p.host, "registered_domain": p.registered_domain,
            "impersonated_brand": brand,
            "reasons": sorted(reasons, key=lambda r: (r["code"].startswith("ml:"), -r["weight"])),
        })
    return out


def scan(url: str) -> dict:
    return scan_many([url])[0]
