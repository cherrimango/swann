"""MIRA regression tests: the SAFE-verdict repair, redirects, attachments, citizen alerts, discovery, agents,
sandbox configuration and the demo sign-in prototype."""
import io

import pytest
from fastapi.testclient import TestClient

from raqeeb.security import limiter


@pytest.fixture()
def c(monkeypatch):
    monkeypatch.setenv("MIRA_DEMO", "1")
    limiter.reset()
    from server.app import app
    with TestClient(app) as client:
        yield client
    limiter.reset()


def tok(c, email, pw):
    return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"email": email, "password": pw}).json()["token"]}


def admin(c):
    return tok(c, "admin@mira.demo", "MiraDemo2026!")


def analyst(c):
    return tok(c, "analyst@mira.demo", "AnalystDemo2026!")


def citizen(c):
    return tok(c, "citizen@mira.demo", "CitizenDemo2026!")


# ---------- detection repair ----------
def test_canonical_form_removes_scheme_shortcut():
    from raqeeb.features import canonical
    assert canonical("https://www.Example.com/a//b?x=1#frag") == "example.com/a/b?x=1"
    assert canonical("http://example.com/a/b?x=1") == canonical("https://www.example.com/a/b?x=1")


def test_psl_brand_text_in_subdomain_is_not_official():
    from raqeeb.link import pipeline
    r = pipeline.analyse("https://login.uaepass.example.com/auth", "quick")
    assert r["registered_domain"] == "example.com"
    assert not r["official_domain_match"]
    assert r["verdict"] in ("MALICIOUS", "SUSPICIOUS")


def test_unknown_benign_looking_site_is_inconclusive_not_safe():
    from raqeeb.link import pipeline
    r = pipeline.analyse("https://quiet-garden-studio-portfolio.com/about", "quick")
    assert r["verdict"] != "SAFE"
    if r["verdict"] == "INCONCLUSIVE":
        assert any("cannot call this site safe" in x for x in r["limitations"])


def test_official_and_popular_domains_can_be_safe():
    from raqeeb.link import pipeline
    assert pipeline.analyse("https://www.google.com", "quick")["verdict"] == "SAFE"
    assert pipeline.analyse("https://www.doh.gov.ae/en", "quick")["verdict"] == "SAFE"  # .gov.ae restricted zone


def test_phishing_on_user_content_platforms_is_not_capped_as_popular():
    from raqeeb.engine import scan_many
    for u in ("https://sites.google.com/view/adcb-verify-account/home", "https://docs.google.com/forms/d/e/1FAIpQ/viewform?usp=login-verify"):
        r = scan_many([u])[0]
        assert r["verdict"] in ("phishing", "suspicious"), u
        assert "popular_domain" not in [x["code"] for x in r["reasons"]]


def test_hosting_provider_subdomain_is_not_safe():
    from raqeeb.engine import scan_many
    r = scan_many(["http://starpsscfc.wpengine.com"])[0]
    assert r["verdict"] != "safe"


def test_sandbox_failure_never_yields_safe(monkeypatch):
    from raqeeb.link import pipeline, sandbox, static_analyzer, visual
    monkeypatch.setattr(sandbox, "analyse", lambda url, shot=None: {"available": False, "error": "connection refused"})
    monkeypatch.setattr(static_analyzer, "domain_features", lambda v: {k: {"available": False, "error": "offline"} for k in ("rdap", "dns", "certificate")})
    monkeypatch.setattr(visual, "analyse", lambda shot, text: {"available": False, "reason": "no screenshot", "brand_text_found": [], "ocr": {"available": False}})
    r = pipeline.analyse("https://quiet-garden-studio-portfolio.com/", "deep")
    assert r["verdict"] != "SAFE"
    assert r["redirects"]["all_destinations_analysed"] is False and "connection refused" in r["redirects"]["stopped_reason"]


def test_model_is_the_full_url_model_with_calibration():
    from raqeeb.engine import model
    m = model()
    assert m.meta["mode"] == "url" and m.meta.get("canonical") and m.meta.get("calibration")
    p, _, _ = m.predict(["http://paypal-account-verify-login.top/secure/signin.php", "https://www.wikipedia.org"])
    assert p[0] > m.threshold > p[1]


# ---------- redirects ----------
def test_redirect_analysis_counts_hops_domains_and_loops():
    from raqeeb.link import redirects
    chain = [{"status": 301, "url": "https://bit.ly/x"}, {"status": 302, "url": "https://trk.invalid-demo.com/c"}, {"status": 200, "url": "https://scam.top/pay"}]
    r = redirects.analyse(chain, "https://bit.ly/x", "https://scam.top/pay")
    assert r["redirect_count"] == 2 and r["domains"] == ["bit.ly", "invalid-demo.com", "scam.top"] and r["shortener_in_chain"]
    assert r["all_destinations_analysed"] and r["final_registered_domain"] == "scam.top"
    loop = redirects.analyse([{"status": 302, "url": "https://a.com/1"}, {"status": 302, "url": "https://a.com/1"}], "https://a.com/1", None)
    assert loop["loop"] and not loop["all_destinations_analysed"]
    long = redirects.analyse([{"status": 302, "url": f"https://h{i}.com/"} for i in range(30)], "https://h0.com/", None)
    assert long["truncated"] and "hop limit" in long["stopped_reason"]


# ---------- attachments ----------
def _qr_png(text):
    import qrcode
    buf = io.BytesIO()
    qrcode.make(text).save(buf, format="PNG")
    return buf.getvalue()


def test_attachment_qr_image_is_decoded_and_link_scanned(c):
    r = c.post("/api/v1/attachments/analyze", files={"file": ("qr.png", _qr_png("http://uaepass-update-id.top/login"), "image/png")})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["qr"]["codes"] == ["http://uaepass-update-id.top/login"]
    assert d["link_scans"][0]["from_qr"] and d["verdict"] in ("MALICIOUS", "SUSPICIOUS")


def test_attachment_rejects_programs_and_unknown_types(c):
    assert c.post("/api/v1/attachments/analyze", files={"file": ("x.png", b"MZ\x90\x00" + b"\x00" * 100, "image/png")}).status_code == 422
    assert c.post("/api/v1/attachments/analyze", files={"file": ("x.bin", bytes(range(256)) * 4, "application/octet-stream")}).status_code == 422


def test_attachment_text_file_with_scam_link(c):
    txt = "Your Salik account is suspended. Pay the fine now: http://salik-fines-pay.top/pay".encode()
    d = c.post("/api/v1/attachments/analyze", files={"file": ("msg.txt", txt, "text/plain")}).json()
    assert d["detected_type"] == "text/plain" and d["indicators"]["urls"] and d["verdict"] in ("MALICIOUS", "SUSPICIOUS")


# ---------- citizen alerts ----------
def test_citizen_alert_workflow_enforces_review_approval_and_honest_delivery(c):
    ana, adm, cit = analyst(c), admin(c), citizen(c)
    body = {"category": "phishing_link", "severity": "high", "channels": ["in_app", "sms"],
            "content": {"en": {"title": "Fake UAE PASS links", "description": "Messages ask you to re-verify your ID."}, "ar": {"title": "", "description": ""}}}
    a = c.post("/api/v1/notifications", json=body, headers=ana).json()
    assert a["status"] == "draft"
    assert c.post(f"/api/v1/notifications/{a['id']}/submit", headers=ana).status_code == 409  # Arabic missing
    body["content"]["ar"] = {"title": "روابط مزيفة", "description": "رسائل تطلب إعادة التحقق من الهوية."}
    a = c.put(f"/api/v1/notifications/{a['id']}", json=body, headers=ana).json()
    assert a["version"] == 2
    c.post(f"/api/v1/notifications/{a['id']}/submit", headers=ana)
    assert c.post(f"/api/v1/notifications/{a['id']}/review", json={"approve": True}, headers=ana).status_code == 409  # own alert
    assert c.post(f"/api/v1/notifications/{a['id']}/approve", headers=ana).status_code == 403  # analysts can't approve
    assert c.post(f"/api/v1/notifications/{a['id']}/review", json={"approve": True}, headers=adm).json()["status"] == "reviewed"
    assert c.post(f"/api/v1/notifications/{a['id']}/publish", headers=adm).status_code == 409  # not approved yet
    c.post(f"/api/v1/notifications/{a['id']}/approve", headers=adm)
    p = c.post(f"/api/v1/notifications/{a['id']}/publish", headers=adm).json()
    st = {d["channel"]: d["status"] for d in p["deliveries"]}
    assert st["in_app"] == "delivered_in_app" and st["sms"] == "not_configured"
    mine = c.get("/api/v1/notifications", headers=cit).json()["alerts"]
    assert any(x["id"] == a["id"] for x in mine)
    assert c.post(f"/api/v1/notifications/{a['id']}/engage", json={"action": "acknowledged"}, headers=cit).json()["ok"]
    assert c.get("/api/v1/notifications", headers=adm).json()["alerts"][0]["engagement"].get("acknowledged") == 1
    assert c.post("/api/v1/notifications", json=body, headers=cit).status_code == 403


def test_ai_draft_is_labelled_and_bilingual(c):
    d = c.post("/api/v1/notifications/draft", json={"category": "bank_otp", "brands": ["ADCB"]}, headers=analyst(c)).json()
    assert d["ai_drafted"] and "not an official statement" in d["notice"] and d["content"]["ar"]["title"]


# ---------- discovery ----------
def test_discovery_records_new_duplicates_missing_keys_and_failures(c, monkeypatch):
    from raqeeb import discovery
    feed = "http://new-scam-1.top/a\nhttp://new-scam-2.top/b\n# comment\n"
    monkeypatch.setattr(discovery, "safe_get", lambda url, timeout=20: (None, [], feed))
    r1 = discovery.collect("openphish")
    r2 = discovery.collect("openphish")
    assert (r1["status"], r1["new_indicators"]) == ("ok", 2) and (r2["new_indicators"], r2["duplicates"]) == (0, 2)
    monkeypatch.delenv("MIRA_PHISHTANK_APP_KEY", raising=False)
    assert discovery.collect("phishtank")["status"] == "blocked_missing_key"
    monkeypatch.delenv("MIRA_URLHAUS_AUTH_KEY", raising=False)
    assert discovery.collect("urlhaus_recent")["status"] == "blocked_missing_key"

    def boom(url, timeout=20):
        raise ConnectionError("network unreachable")
    monkeypatch.setattr(discovery, "safe_get", boom)
    f = discovery.collect("phishing_database_today")
    assert f["status"] == "failed" and "unreachable" in f["error"]
    st = c.get("/api/v1/intelligence/sources/status", headers=analyst(c)).json()["discovery"]
    assert {s["id"]: s["health"] for s in st["sources"]}["openphish"] == "healthy"
    # a discovered indicator now matches in signature checks, marked as not analyst-verified
    from raqeeb.link import pipeline
    rep = pipeline.analyse("http://new-scam-1.top/a", "quick")
    m = [x for x in rep["signature_result"]["matches"] if x["source"] == "mira_discovery"]
    assert m and "not yet analyst-verified" in m[0]["classification"]


# ---------- agents, sandbox config, models, reports ----------
def test_fourteen_agents_with_structured_results(c):
    h = analyst(c)
    lst = c.get("/api/v1/agents", headers=h).json()
    assert len(lst) == 14
    r = c.post("/api/v1/agents/phishing/run", json={"input": "http://adcb-secure-login.top/verify"}, headers=h).json()
    assert set(r) >= {"agent", "task", "result", "evidence", "confidence", "source", "timestamp", "limitations", "recommended_action"}
    assert r["result"]["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    assert c.post("/api/v1/agents/seasonal/run", json={}, headers=h).status_code == 200


def test_sandbox_configuration_is_for_officials_only(c):
    assert c.get("/api/v1/sandbox/configuration").status_code == 401
    assert c.get("/api/v1/sandbox/configuration", headers=citizen(c)).status_code == 403
    cfg = c.get("/api/v1/sandbox/configuration", headers=analyst(c)).json()
    assert {g["name"] for g in cfg["groups"]} >= {"Navigation", "Browser", "Network and security"}


def test_models_metrics_and_reports_endpoints(c):
    m = c.get("/api/v1/models/metrics").json()
    assert m["deployed"]["mode"] == "url" and m["evaluation_mira"]["evaluation"]["main"]["recall"] > 0
    cit = citizen(c)
    r = c.post("/api/v1/reports", data={"type": "sms", "text": "Pay your fine at http://adpolice-fines.top/pay"}, headers=cit).json()
    assert r["ref"]
    assert any(x["ref"] == r["ref"] for x in c.get("/api/v1/reports", headers=cit).json())
    assert c.get(f"/api/v1/reports/{r['ref']}", headers=analyst(c)).json()["ref"] == r["ref"]


# ---------- demo sign-in prototype ----------
def test_demo_signin_prototype_issues_one_time_session(c):
    s = c.post("/api/signin-demo/start").json()
    assert s["simulated"] and s["qr_payload"].startswith("MIRA-DEMO-SIGNIN:")
    assert c.get(f"/api/signin-demo/{s['request_id']}").json()["state"] == "waiting"
    assert c.post(f"/api/signin-demo/{s['request_id']}/respond", json={"account": "analyst", "approve": True}).status_code == 400  # no consent
    c.post(f"/api/signin-demo/{s['request_id']}/respond", json={"account": "analyst", "approve": True, "consent": True})
    p = c.get(f"/api/signin-demo/{s['request_id']}").json()
    assert p["app"] == "command" and p["token"]
    assert c.get("/api/auth/me", headers={"Authorization": "Bearer " + p["token"]}).json()["email"] == "analyst@mira.demo"
    assert "token" not in c.get(f"/api/signin-demo/{s['request_id']}").json()  # cannot be replayed


def test_demo_signin_disabled_outside_demo_mode(monkeypatch):
    monkeypatch.delenv("MIRA_DEMO", raising=False)
    from server.app import app
    with TestClient(app) as client:
        assert client.post("/api/signin-demo/start").status_code == 403


def test_pages_served_and_no_old_branding(c):
    for path in ("/", "/command", "/app", "/signin"):
        html = c.get(path).text
        assert "RAQEEB" not in html and "رقيب" not in html and "mark-flag" not in html
    assert c.get("/static/shared/mira-mark.png").status_code == 200
