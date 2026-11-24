"""SAWNN regression tests: the SAFE-verdict repair, redirects, attachments, citizen alerts, discovery, agents,
sandbox configuration and the demo sign-in prototype."""
import io

import pytest
from fastapi.testclient import TestClient

from raqeeb.security import limiter


@pytest.fixture()
def c(monkeypatch):
    monkeypatch.setenv("SAWNN_DEMO", "1")
    limiter.reset()
    from server.app import app
    with TestClient(app) as client:
        yield client
    limiter.reset()


def tok(c, email, pw):
    return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"email": email, "password": pw}).json()["token"]}


def admin(c):
    return tok(c, "admin@sawnn.demo", "SawnnDemo2026!")


def analyst(c):
    return tok(c, "analyst@sawnn.demo", "AnalystDemo2026!")


def citizen(c):
    return tok(c, "citizen@sawnn.demo", "CitizenDemo2026!")


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
    monkeypatch.delenv("SAWNN_PHISHTANK_APP_KEY", raising=False)
    assert discovery.collect("phishtank")["status"] == "blocked_missing_key"
    monkeypatch.delenv("SAWNN_URLHAUS_AUTH_KEY", raising=False)
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
    m = [x for x in rep["signature_result"]["matches"] if x["source"] == "sawnn_discovery"]
    assert m and "not yet analyst-verified" in m[0]["classification"]


# ---------- agents, sandbox config, models, reports ----------
def test_sixteen_agents_run_through_the_orchestrator_with_handoffs(c):
    h = analyst(c)
    lst = c.get("/api/v1/agents", headers=h).json()
    assert len(lst) == 16 and {"url_analysis", "sentiment_social_engineering"} <= {a["id"] for a in lst}
    w = c.post("/api/v1/agents/url_analysis/run", json={"input": "http://adcb-secure-login.top/verify"}, headers=h).json()
    agents = [t["agent"] for t in w["tasks"]]
    assert agents[:2] == ["url_analysis", "phishing_intelligence"] and "uae_brand_impersonation" in agents
    for t in w["tasks"]:
        assert t["status"] == "completed" and t["duration_ms"] is not None and t["id"].startswith("TSK-")
        assert set(t) >= {"agent", "status", "input_refs", "findings", "evidence", "confidence", "sources", "errors", "recommended_action"}
    pi = next(t for t in w["tasks"] if t["agent"] == "phishing_intelligence")
    assert pi["parent_id"] == w["tasks"][0]["id"] and pi["findings"]["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    assert w["status"] == "completed"
    act = c.get("/api/v1/agents/activity", headers=h).json()
    assert any(a["agent"] == "phishing_intelligence" and a["completed"] >= 1 for a in act["agents"])
    assert c.post("/api/v1/agents/seasonal/run", json={}, headers=h).json()["status"] == "completed"


def test_failing_agent_is_recorded_not_hidden(c):
    from raqeeb import orchestrator
    w = orchestrator.run_sync("manual", {"url": ""}, "test", "url_analysis")
    t = w["tasks"][0]
    assert t["status"] == "failed" and t["errors"] and w["status"] == "failed"


def test_citizen_report_enters_the_agent_pipeline(c):
    from raqeeb import orchestrator
    r = c.post("/api/v1/reports", data={"type": "sms", "text": "Your account will be suspended today. Pay the fine now: http://adpolice-fines.top/pay"},
               headers=citizen(c)).json()
    assert r["workflow_id"]
    orchestrator.drain()
    w = orchestrator.workflow(r["workflow_id"])
    agents = {t["agent"] for t in w["tasks"]}
    assert {"message_intelligence", "sentiment_social_engineering", "url_analysis", "phishing_intelligence"} <= agents


def test_discovery_pipeline_creates_investigations_and_notifies(c, monkeypatch):
    from raqeeb import discovery, orchestrator
    events = []
    orchestrator.set_notifier(lambda ev, data: events.append((ev, data)))
    feed = "http://uaepass-renew-account.top/login\nhttps://www.wikipedia.org/wiki/Abu_Dhabi\n"
    monkeypatch.setattr(discovery, "safe_get", lambda url, timeout=20, headers=None: (None, [], feed))
    assert discovery.collect("openphish")["new_indicators"] >= 1
    q = orchestrator.process_discoveries(10)
    orchestrator.drain()
    w = orchestrator.workflow(q["hunter_workflow"])
    assert w["tasks"][0]["agent"] == "global_threat_hunter" and w["tasks"][0]["handoffs"]
    st = discovery.status()
    assert st["processing"]["by_status"].get("processed", 0) >= 2 and st["processing"]["investigations_created"] >= 1
    from raqeeb.db import db, one
    ind = one(db().execute("SELECT * FROM indicators WHERE value LIKE '%uaepass-renew-account%'"))
    assert ind["verdict"] in ("MALICIOUS", "SUSPICIOUS") and ind["threat_id"]
    t = one(db().execute("SELECT status, source FROM threats WHERE id=?", (ind["threat_id"],)))
    assert t["status"] == "new" and "Discovery Engine" in t["source"]  # analysts decide; nothing is auto-approved
    assert any(ev == "discovery_alert" for ev, _ in events)
    wiki = one(db().execute("SELECT * FROM indicators WHERE value LIKE '%wikipedia%'"))
    assert wiki["threat_id"] is None
    orchestrator.set_notifier(None)


def test_scheduler_runs_jobs_and_records_failures(c, monkeypatch):
    from raqeeb import discovery, orchestrator

    def offline(url, timeout=20, headers=None):
        raise ConnectionError("network unreachable")
    monkeypatch.setattr(discovery, "safe_get", offline)
    r = orchestrator.run_job("feeds_high_priority")
    assert r["status"] in ("failed", "partial") and r["error"]
    assert orchestrator.run_job("campaign_correlation")["status"] == "ok"
    st = c.get("/api/v1/scheduler", headers=analyst(c)).json()
    jobs = {j["name"]: j for j in st["jobs"]}
    assert jobs["feeds_high_priority"]["last_status"] in ("failed", "partial") and jobs["feeds_high_priority"]["next_run"]
    assert st["running"] is False  # tests run with the scheduler thread off, and the API says so


def test_social_engineering_analysis_en_ar_is_supporting_only(c):
    from raqeeb.messages import check_message
    from raqeeb.sentiment import analyse
    en = analyse("URGENT: your account will be suspended within 24 hours. Pay the fee now and do not tell anyone.")
    assert en["language"] == "en" and {"suspension", "deadline", "payment", "secrecy"} <= {i["category"] for i in en["indicators"]}
    assert en["pressure_with_action"] and en["sentiment"]["label"] == "negative"
    ar = analyse("تم إيقاف حسابك. ادفع الغرامة خلال 24 ساعة وشارك رمز التحقق")
    assert ar["language"] == "ar" and {"suspension", "payment", "credentials"} <= {i["category"] for i in ar["indicators"]}
    # pressure wording alone never reaches SUSPICIOUS
    m = check_message("Urgent!!! Final warning, act immediately, danger, your account is at risk")
    assert m["risk_score"] < 35 and m["social_engineering"]["manipulation_score"] > 0
    r = c.post("/api/v1/analysis/social-engineering", json={"text": "مبروك! لقد فزت بجائزة"}).json()
    assert r["language"] == "ar" and any(i["category"] == "reward" for i in r["indicators"])


def test_invisible_characters_from_copied_links_are_removed():
    from raqeeb.link import pipeline, url_validator
    v = url_validator.validate("\u200ehttps://uaepass-verify.top/login\u200f")
    assert v["normalised_url"] == "https://uaepass-verify.top/login" and v["flags"]["invisible_characters"]
    r = pipeline.analyse("\u202ehttps://example-login.top/pay", "quick")
    assert any(e["signal"] == "rtl_override" for e in r["evidence"])


def test_sandbox_configuration_is_for_officials_only(c):
    assert c.get("/api/v1/sandbox/configuration").status_code == 401
    assert c.get("/api/v1/sandbox/configuration", headers=citizen(c)).status_code == 403
    cfg = c.get("/api/v1/sandbox/configuration", headers=analyst(c)).json()
    assert {g["name"] for g in cfg["groups"]} >= {"Navigation", "Browser", "Network and security"}


def test_models_metrics_and_reports_endpoints(c):
    m = c.get("/api/v1/models/metrics").json()
    assert m["deployed"]["mode"] == "url" and m["evaluation_sawnn"]["evaluation"]["main"]["recall"] > 0
    cit = citizen(c)
    r = c.post("/api/v1/reports", data={"type": "sms", "text": "Pay your fine at http://adpolice-fines.top/pay"}, headers=cit).json()
    assert r["ref"]
    assert any(x["ref"] == r["ref"] for x in c.get("/api/v1/reports", headers=cit).json())
    assert c.get(f"/api/v1/reports/{r['ref']}", headers=analyst(c)).json()["ref"] == r["ref"]


# ---------- demo sign-in prototype ----------
def test_demo_signin_prototype_issues_one_time_session(c):
    s = c.post("/api/signin-demo/start").json()
    assert s["simulated"] and s["qr_payload"].startswith("SAWNN-DEMO-SIGNIN:")
    assert c.get(f"/api/signin-demo/{s['request_id']}").json()["state"] == "waiting"
    assert c.post(f"/api/signin-demo/{s['request_id']}/respond", json={"account": "analyst", "approve": True}).status_code == 400  # no consent
    c.post(f"/api/signin-demo/{s['request_id']}/respond", json={"account": "analyst", "approve": True, "consent": True})
    p = c.get(f"/api/signin-demo/{s['request_id']}").json()
    assert p["app"] == "command" and p["token"]
    assert c.get("/api/auth/me", headers={"Authorization": "Bearer " + p["token"]}).json()["email"] == "analyst@sawnn.demo"
    assert "token" not in c.get(f"/api/signin-demo/{s['request_id']}").json()  # cannot be replayed


def test_demo_signin_disabled_outside_demo_mode(monkeypatch):
    monkeypatch.delenv("SAWNN_DEMO", raising=False)
    from server.app import app
    with TestClient(app) as client:
        assert client.post("/api/signin-demo/start").status_code == 403


def test_pages_served_and_no_old_branding(c):
    for path in ("/", "/command", "/app", "/signin"):
        html = c.get(path).text
        assert "RAQEEB" not in html and "رقيب" not in html and "mark-flag" not in html
    assert c.get("/static/shared/sawnn-mark.png").status_code == 200
