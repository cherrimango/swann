"""Browser sandbox: visits a hostile URL in a disposable headless Chromium and records what the page does.

Application-level isolation implemented here:
  * a fresh browser process per scan, closed afterwards; no persistent profile, no stored credentials;
  * every request (navigation, redirects, sub-resources) is re-checked: no loopback, private, link-local, metadata
    or non-web ports, so the page cannot reach internal services;
  * downloads are refused, dialogs dismissed, navigation time-boxed;
  * nothing is ever typed or submitted.
Network-level isolation (a disposable container with an egress firewall, CPU/memory limits) is a deployment step:
see infrastructure/sandbox in the README. Without Playwright the stage falls back to a static fetch (no JavaScript).
"""
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin

from ..security import UnsafeTarget, check_url, safe_get
from ..urlparse import parse

UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
      "Version/17.5 Mobile/15E148 Safari/604.1")
NAV_TIMEOUT_MS = int(os.environ.get("MIRA_SANDBOX_TIMEOUT") or 15000)
PAYMENT_RX = re.compile(r"card|cc-?num|cvv|cvc|expiry|exp-?date|iban|account.?number|بطاقة", re.I)

EXTRACT_JS = r"""() => {
  const vis = el => { const s = getComputedStyle(el); return s.display !== 'none' && s.visibility !== 'hidden' && el.offsetWidth + el.offsetHeight > 0; };
  const inputs = [...document.querySelectorAll('input,select,textarea')].map(i => ({
    type: (i.type || i.tagName).toLowerCase(), name: (i.name || i.id || '').slice(0, 60),
    placeholder: (i.placeholder || '').slice(0, 80), autocomplete: (i.autocomplete || '').slice(0, 40), hidden: !vis(i) }));
  return {
    title: document.title.slice(0, 200),
    meta_description: (document.querySelector('meta[name="description"]') || {}).content || null,
    text: document.body ? document.body.innerText.slice(0, 20000) : '',
    forms: [...document.forms].map(f => ({ action: f.getAttribute('action') || '', method: (f.method || 'get').toLowerCase() })),
    inputs,
    links: [...document.querySelectorAll('a[href]')].map(a => a.href).slice(0, 400),
    scripts: [...document.scripts].map(s => s.src).filter(Boolean).slice(0, 200),
    iframes: [...document.querySelectorAll('iframe')].map(f => f.src).slice(0, 50),
    images: [...document.images].map(i => ({ src: i.src, alt: (i.alt || '').slice(0, 80) })).slice(0, 100),
    hidden_elements: [...document.querySelectorAll('body *')].filter(e => !vis(e)).length,
    width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight,
  };
}"""


def _summarise(data: dict, final_url: str) -> dict:
    host = parse(final_url).host
    inputs = data.get("inputs", [])
    types = [i["type"] for i in inputs]
    form_dest = []
    for f in data.get("forms", []):
        act = urljoin(final_url, f["action"]) if f["action"] else final_url
        form_dest.append({"action": act, "method": f["method"], "external": parse(act).host != host})
    third = sorted({parse(u).registered_domain for u in data.get("scripts", []) + data.get("iframes", []) + [i["src"] for i in data.get("images", [])]
                    if u.startswith("http") and parse(u).registered_domain and parse(u).registered_domain != parse(final_url).registered_domain})
    payment = any(PAYMENT_RX.search(f"{i['name']} {i['placeholder']} {i['autocomplete']}") for i in inputs) or "cc-number" in str(inputs)
    return {
        "page_title": data.get("title"), "meta_description": data.get("meta_description"),
        "visible_text": (data.get("text") or "")[:5000], "forms": form_dest,
        "input_fields": len(inputs), "password_fields": types.count("password"), "email_fields": types.count("email"),
        "telephone_fields": types.count("tel"), "payment_fields": payment,
        "hidden_inputs": sum(1 for i in inputs if i["hidden"] and i["type"] != "hidden"),
        "external_links": sum(1 for u in data.get("links", []) if u.startswith("http") and parse(u).host != host),
        "scripts": len(data.get("scripts", [])), "iframes": len(data.get("iframes", [])),
        "hidden_elements": data.get("hidden_elements"), "third_party_domains": third[:40],
        "logo_references": [i["src"] for i in data.get("images", []) if re.search(r"logo|brand|شعار", i["src"] + i["alt"], re.I)][:10],
        "page_dimensions": {"width": data.get("width"), "height": data.get("height")} if data.get("width") else None,
    }


def _browser(url: str, shot: Path | None) -> dict:
    from playwright.sync_api import sync_playwright
    t0 = time.time()
    chain, blocked, downloads = [], [], []
    with sync_playwright() as pw:
        exe = os.environ.get("MIRA_CHROMIUM")
        b = pw.chromium.launch(executable_path=exe or None, args=["--no-sandbox"] if exe else [])
        try:
            ctx = b.new_context(user_agent=UA, viewport={"width": 390, "height": 844}, accept_downloads=False,
                                java_script_enabled=True, ignore_https_errors=True, service_workers="block")
            pg = ctx.new_page()

            def guard(route):
                try:
                    check_url(route.request.url)
                    route.continue_()
                except UnsafeTarget:
                    blocked.append(route.request.url[:200])
                    route.abort()
            pg.route("**/*", guard)
            pg.on("dialog", lambda d: d.dismiss())
            pg.on("download", lambda d: (downloads.append(d.suggested_filename), d.cancel()))
            pg.on("response", lambda r: chain.append({"status": r.status, "url": r.url[:300]})
                  if r.request.is_navigation_request() and r.request.frame == pg.main_frame else None)
            resp = pg.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            pg.wait_for_timeout(1500)  # let client-side redirects and scripts run
            data = pg.evaluate(EXTRACT_JS)
            if shot:
                shot.parent.mkdir(parents=True, exist_ok=True)
                pg.screenshot(path=str(shot), full_page=False)
            final = pg.url
            status = resp.status if resp else None
        finally:
            b.close()
    return {"available": True, "mode": "headless browser", "initial_url": url, "final_url": final, "http_status": status,
            "redirect_chain": chain, "redirect_count": max(0, len(chain) - 1), "load_seconds": round(time.time() - t0, 2),
            "blocked_internal_requests": blocked, "downloads_blocked": downloads, "https": final.startswith("https://"),
            "screenshot": bool(shot and shot.exists()), **_summarise(data, final)}


def _static(url: str) -> dict:
    from bs4 import BeautifulSoup
    t0 = time.time()
    r, chain, html = safe_get(url, headers={"User-Agent": UA}, timeout=8)
    soup = BeautifulSoup(html, "html.parser")
    data = {
        "title": (soup.title.string or "").strip()[:200] if soup.title and soup.title.string else "",
        "meta_description": (soup.find("meta", attrs={"name": "description"}) or {}).get("content"),
        "text": soup.get_text(" ", strip=True)[:20000],
        "forms": [{"action": f.get("action", ""), "method": (f.get("method") or "get").lower()} for f in soup.find_all("form")],
        "inputs": [{"type": (i.get("type") or i.name).lower(), "name": (i.get("name") or i.get("id") or "")[:60],
                    "placeholder": (i.get("placeholder") or "")[:80], "autocomplete": (i.get("autocomplete") or "")[:40],
                    "hidden": "display:none" in (i.get("style") or "").replace(" ", "")} for i in soup.find_all(["input", "select", "textarea"])],
        "links": [urljoin(r.url, a["href"]) for a in soup.find_all("a", href=True)][:400],
        "scripts": [urljoin(r.url, s["src"]) for s in soup.find_all("script", src=True)][:200],
        "iframes": [urljoin(r.url, f.get("src", "")) for f in soup.find_all("iframe")][:50],
        "images": [{"src": urljoin(r.url, i.get("src", "")), "alt": (i.get("alt") or "")[:80]} for i in soup.find_all("img")][:100],
        "hidden_elements": None,
    }
    return {"available": True, "mode": "static fetch (no JavaScript; Playwright not available)", "initial_url": url,
            "final_url": r.url, "http_status": r.status_code, "redirect_chain": chain, "redirect_count": max(0, len(chain) - 1),
            "load_seconds": round(time.time() - t0, 2), "https": r.url.startswith("https://"), "screenshot": False,
            **_summarise(data, r.url)}


def analyse(url: str, shot: Path | None = None) -> dict:
    """Visit the URL. Never raises: failures are returned with available=False and the error."""
    if os.environ.get("MIRA_SANDBOX_ENABLED", "1").lower() in ("0", "false", "no"):
        return {"available": False, "error": "sandbox disabled by MIRA_SANDBOX_ENABLED"}
    try:
        check_url(url)
    except UnsafeTarget as e:
        return {"available": False, "error": f"not visited: {e}"}
    try:
        import playwright  # noqa: F401
        try:
            return _browser(url, shot)
        except Exception as e:  # noqa: BLE001 - browser missing or page failed: try the static fetch
            browser_error = str(e).splitlines()[0][:200]
    except ImportError:
        browser_error = "Playwright not installed"
    try:
        out = _static(url)
        out["browser_error"] = browser_error
        return out
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:200], "browser_error": browser_error}
