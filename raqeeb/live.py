"""Live enrichment (needs internet): redirects, domain age, hosting, TLS, page content, cloaking, screenshot.

Every network call is time-boxed and failure-tolerant: a dead site still gets a verdict from the offline engine.
Pages are fetched read-only; nothing is ever submitted to a form.
"""
import datetime as dt
import difflib
import hashlib
import json
import re
import socket
import ssl
from pathlib import Path

import requests
from types import SimpleNamespace

from .brands import BRANDS, official_brand
from .engine import TOP_LEGIT, scan
from .evidence import write_pack
from .security import UnsafeTarget, check_url, safe_get
from .urlparse import parse

UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
UA_BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
TIMEOUT = 8

SENSITIVE = {
    "password": [r"type=[\"']?password", r"كلمة (?:المرور|السر)"],
    "card": [r"card.?number|cardnumber|\bcc-?num|\bpan\b", r"\bcvv\b|\bcvc\b|security code", r"expir", r"رقم البطاقة|رمز الأمان|تاريخ الانتهاء"],
    "otp": [r"\botp\b|one.?time|verification code", r"رمز التحقق|الرمز المرسل"],
    "emirates_id": [r"emirates.?id|\b784-?\d{4}", r"رقم الهوية|الهوية الإماراتية"],
}
URGENCY = [r"overdue|suspend|blocked|within 24 hours|avoid (?:a )?fine|final notice|immediately",
           r"متأخر|إيقاف|حظر|خلال 24 ساعة|تجنب الغرامة|فوراً"]


def now():
    utc = dt.datetime.now(dt.timezone.utc)
    return {"utc": utc.isoformat(timespec="seconds"),
            "uae": utc.astimezone(dt.timezone(dt.timedelta(hours=4))).isoformat(timespec="seconds")}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url, ua):
    """SSRF-safe fetch: every redirect hop is checked against private / internal addresses."""
    r, chain, text = safe_get(url, headers={"User-Agent": ua, "Accept-Language": "ar-AE,en;q=0.8"}, timeout=TIMEOUT)
    return SimpleNamespace(text=text, url=r.url, status_code=r.status_code), chain


def client_redirect(html: str):
    m = re.search(r"http-equiv=[\"']?refresh[\"']?[^>]*url=([^\"'>\s]+)", html, re.I) or \
        re.search(r"(?:window\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']", html) or \
        re.search(r"location\.replace\([\"']([^\"']+)[\"']\)", html)
    return m.group(1) if m else None


def rdap_domain(domain):
    try:
        j = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT).json()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120]}
    out = {"registrar": None, "created": None, "abuse_email": None,
           "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])]}
    for ev in j.get("events", []):
        if ev.get("eventAction") == "registration":
            out["created"] = ev.get("eventDate")
    for ent in j.get("entities", []):
        roles = ent.get("roles", [])
        vcard = ent.get("vcardArray", [None, []])[1]
        fn = next((v[3] for v in vcard if v[0] == "fn"), None)
        if "registrar" in roles:
            out["registrar"] = fn
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    sv = sub.get("vcardArray", [None, []])[1]
                    out["abuse_email"] = next((v[3] for v in sv if v[0] == "email"), None)
    if out["created"]:
        try:
            created = dt.datetime.fromisoformat(out["created"].replace("Z", "+00:00"))
            out["age_days"] = (dt.datetime.now(dt.timezone.utc) - created).days
        except ValueError:
            pass
    return out


def hosting(host):
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        return {"error": str(e)[:120]}
    out = {"ip": ip}
    try:
        j = requests.get(f"https://rdap.org/ip/{ip}", timeout=TIMEOUT).json()
        out.update({"network": j.get("name"), "country": j.get("country"),
                    "handle": j.get("handle")})
    except Exception as e:  # noqa: BLE001
        out["rdap_error"] = str(e)[:120]
    return out


def tls(host):
    try:
        check_url(f"https://{host}/")
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
            c = ss.getpeercert()
        nb = dt.datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        issuer = dict(x[0] for x in c.get("issuer", ()))
        return {"issuer": issuer.get("organizationName"), "not_before": nb.isoformat(),
                "cert_age_days": (dt.datetime.now(dt.timezone.utc) - nb).days}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120]}


def analyse_html(html: str, host: str):
    low = html.lower()
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    found = {k: any(re.search(p, low if p.isascii() else html, re.I) for p in pats) for k, pats in SENSITIVE.items()}
    urgency = any(re.search(p, low if p.isascii() else html, re.I) for p in URGENCY)
    actions = re.findall(r"<form[^>]+action=[\"']?([^\"' >]+)", html, re.I)
    ext_actions = sorted({parse(a).host for a in actions if a.startswith("http") and parse(a).host != host})
    title_text = title.group(1).strip()[:150] if title else ""
    in_title, in_body = [], []
    off = official_brand(parse("http://" + host))
    for b in BRANDS:
        if off and off["id"] == b["id"]:
            continue
        terms = [t for t in b["content_terms"] if len(t) >= 4]
        if any((t.lower() in title_text.lower()) if t.isascii() else (t in title_text) for t in terms):
            in_title.append(b["name"])
        elif any((t.lower() in low) if t.isascii() else (t in html) for t in terms):
            in_body.append(b["name"])
    return {"title": title_text or None, "asks_for": [k for k, v in found.items() if v],
            "urgency_language": urgency, "external_form_actions": ext_actions,
            "brands_in_title": in_title[:5], "brands_in_content": in_body[:5]}


def screenshot(url, dest: Path):
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page(user_agent=UA_MOBILE, viewport={"width": 390, "height": 844})

            def guard(route):  # the headless browser may not reach internal addresses either
                try:
                    check_url(route.request.url)
                    route.continue_()
                except UnsafeTarget:
                    route.abort()
            pg.route("**/*", guard)
            pg.goto(url, timeout=15000, wait_until="domcontentloaded")
            pg.screenshot(path=str(dest), full_page=False)
            b.close()
        return dest
    except Exception:  # noqa: BLE001 - playwright/browser not installed or page failed
        return None


def enrich(result: dict, evidence_dir: Path | None = None) -> dict:
    url = parse(result["url"]).url
    live = {"checked_at": now()}
    risk, reasons = result["risk_score"], list(result["reasons"])

    def add(code, en, ar, floor=None, bump=0.0):
        nonlocal risk
        reasons.append({"code": code, "en": en, "ar": ar, "weight": 4})
        if floor is not None:
            risk = max(risk, floor)
        risk = min(100.0, risk + bump)

    html, final = "", url
    try:
        r, chain = fetch(url, UA_MOBILE)
        html, final = r.text[:2_000_000], r.url
        nxt = client_redirect(html)
        if nxt and nxt.startswith("http"):
            r2, chain2 = fetch(nxt, UA_MOBILE)
            chain += chain2
            html, final = r2.text[:2_000_000], r2.url
        live["redirect_chain"] = chain
        live["final_url"] = final
        live["html_sha256"] = sha256(html.encode("utf-8", "ignore"))
    except Exception as e:  # noqa: BLE001
        live["fetch_error"] = str(e)[:160]

    fp = parse(final)
    if final != url and fp.host != parse(url).host:
        fin = scan(final)
        live["final_scan"] = {"url": final, "risk_score": fin["risk_score"], "verdict": fin["verdict"]}
        if fin["risk_score"] > risk:
            add("redirect_target", f"Redirects to a risky destination: {fp.host}", f"يعيد التوجيه إلى وجهة خطرة: {fp.host}",
                floor=fin["risk_score"])
            if fin.get("impersonated_brand"):
                result["impersonated_brand"] = fin["impersonated_brand"]

    live["whois"] = rdap_domain(fp.registered_domain)
    live["hosting"] = hosting(fp.host)
    live["tls"] = tls(fp.host) if fp.scheme == "https" else {"note": "no HTTPS"}
    age = live["whois"].get("age_days")
    if age is not None and age < 30 and not official_brand(fp):
        add("new_domain", f"Domain registered only {age} days ago", f"النطاق مسجّل منذ {age} يوماً فقط", bump=15)
    cert_age = live["tls"].get("cert_age_days")
    if cert_age is not None and cert_age < 7 and not official_brand(fp):
        add("new_certificate", f"TLS certificate issued {cert_age} days ago", f"شهادة TLS صادرة منذ {cert_age} أيام", bump=5)

    if html:
        a = analyse_html(html, fp.host)
        live["content"] = a
        sensitive = [k for k in a["asks_for"] if k in ("card", "otp", "emirates_id")]
        if not sensitive and "password" in a["asks_for"] and a["brands_in_title"] and \
                (a["urgency_language"] or a["external_form_actions"]):
            sensitive = ["password"]
        brands = a["brands_in_title"] + (a["brands_in_content"] if sensitive else [])
        if brands and not official_brand(fp) and fp.registered_domain not in TOP_LEGIT:
            names = ", ".join(brands)
            if sensitive:
                add("content_impersonation_harvest",
                    f"Page presents itself as {names} and asks for {', '.join(a['asks_for'])} on a non-official domain",
                    f"الصفحة تنتحل {names} وتطلب بيانات حساسة على نطاق غير رسمي", floor=95)
            else:
                add("content_brand_mention", f"Page title uses {names} branding on a non-official domain",
                    f"عنوان الصفحة يستخدم علامة {names} على نطاق غير رسمي", bump=10)
        elif a["asks_for"] and ("card" in a["asks_for"] or "otp" in a["asks_for"]) and a["urgency_language"]:
            add("urgent_payment_form", "Urgent wording with card / OTP fields", "صياغة عاجلة مع حقول بطاقة أو رمز تحقق", bump=15)
        if a["external_form_actions"]:
            add("external_form", f"Form submits to another domain: {a['external_form_actions'][0]}",
                f"النموذج يرسل البيانات إلى نطاق آخر: {a['external_form_actions'][0]}", bump=10)
        try:
            rb, _ = fetch(url, UA_BOT)
            sim = difflib.SequenceMatcher(None, re.sub(r"\s+", " ", rb.text[:20000]), re.sub(r"\s+", " ", html[:20000])).quick_ratio()
            live["cloaking_similarity"] = round(sim, 3)
            if sim < 0.5:
                add("cloaking", "Shows different content to search-engine bots than to phone users (cloaking)",
                    "يعرض محتوى مختلفاً لروبوتات البحث عن مستخدمي الهاتف (تمويه)", bump=15)
        except Exception:  # noqa: BLE001
            pass

    risk = round(min(100.0, risk), 1)
    result = {**result, "risk_score": risk, "label": int(risk >= 50),
              "verdict": "phishing" if risk >= 50 else ("suspicious" if risk >= 35 else "safe"),
              "reasons": sorted(reasons, key=lambda r: (r["code"].startswith("ml:"), -r["weight"])), "live": live}
    if evidence_dir and risk >= 35:
        shot = None
        if html:
            folder = evidence_dir / sha256(result["url"].encode())[:12]
            folder.mkdir(parents=True, exist_ok=True)
            shot = screenshot(final, folder / "screenshot.png")
        result["evidence_pack"] = str(write_pack(result, html, shot, evidence_dir))
    return result


if __name__ == "__main__":
    import sys
    print(json.dumps(enrich(scan(sys.argv[1]), Path("evidence")), ensure_ascii=False, indent=2))
