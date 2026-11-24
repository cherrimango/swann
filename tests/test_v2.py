"""SAWNN 2.0 acceptance tests: accounts and roles, citizen reporting, verification workflow, community
corroboration, rewards, protection distribution, forecasting and security. Run: pytest -q"""
import base64
import io
import json
import secrets

import pytest
from fastapi.testclient import TestClient

from raqeeb import protection
from raqeeb.security import UnsafeTarget, check_url, limiter

SCAM_SMS = ("Dear customer, your UAE PASS account will be suspended today. Verify now at "
            "https://uaepass-reactivate-{n}.com/login or call 0501234{n:03d}")


@pytest.fixture(scope="module")
def c():
    from server.app import app
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _fresh_limits():
    limiter.reset()


def login(c, email, password):
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def admin(c):
    return login(c, "admin@sawnn.local", "test-admin-password")


def official(c, role):
    email, pw = f"{role}-{secrets.token_hex(3)}@sawnn.local", "official-pass-123"
    assert c.post("/api/admin/users", json={"email": email, "password": pw, "role": role}, headers=admin(c)).status_code == 200
    return login(c, email, pw)


def citizen(c, emirate="Abu Dhabi", public=True, name=None):
    r = c.post("/api/auth/register", json={"email": f"c{secrets.token_hex(4)}@example.ae", "password": "citizen-pass-1",
                                            "emirate": emirate, "public_rank": public, "display_name": name})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def report(c, h, text, rtype="auto", emirate="Abu Dhabi"):
    r = c.post("/api/citizen/report", data={"type": rtype, "text": text, "emirate": emirate}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def set_status(c, h, tid, status, note=""):
    return c.post(f"/api/threats/{tid}/status", json={"status": status, "note": note}, headers=h)


# 1. Officials sign in with a role; citizens register as citizens only.
def test_roles_and_registration(c):
    me = c.get("/api/auth/me", headers=admin(c)).json()
    assert me["role"] == "super_admin" and "approve_block" in me["permissions"]
    h = citizen(c)
    assert c.get("/api/auth/me", headers=h).json()["role"] == "citizen"
    assert c.post("/api/auth/login", json={"email": "admin@sawnn.local", "password": "wrong"}).status_code == 401


# 2. RBAC: citizens can't open SAWNN Command; a read-only supervisor can view but not decide.
def test_rbac(c):
    h = citizen(c)
    assert c.get("/api/threats", headers=h).status_code == 403
    assert c.get("/api/threats").status_code == 401
    sup = official(c, "supervisor")
    assert c.get("/api/threats", headers=sup).status_code == 200
    t = c.post("/api/threats", json={"indicator": "http://rbac-test-scam.top/x"}, headers=admin(c)).json()
    assert set_status(c, sup, t["id"], "confirmed_malicious").status_code == 403
    inv = official(c, "investigation_officer")
    assert c.post(f"/api/threats/{t['id']}/notes", json={"note": "called the hosting provider"}, headers=inv).status_code == 200
    assert c.post(f"/api/threats/{t['id']}/block", json={}, headers=inv).status_code == 403


# 3. A pasted SMS is auto-classified and its link and phone number are extracted and analysed.
def test_report_auto_detects_type_and_indicators(c):
    r = report(c, citizen(c), SCAM_SMS.format(n=3))
    assert r["type"] == "sms" and r["risk"] >= 70
    assert r["links"][0]["brand"] == "UAE PASS"
    assert len(r["threat_refs"]) == 2  # the link and the phone number
    assert r["explanation_en"] and r["explanation_ar"]


# 4. Every report gets a reference and a status the citizen can track; other citizens can't see it.
def test_report_reference_and_tracking(c):
    h = citizen(c)
    r = report(c, h, "http://salik-topup-{}.top/pay".format(secrets.token_hex(2)))
    assert r["ref"].startswith("R-") and r["status"] == "under_review"
    assert c.get(f"/api/citizen/reports/{r['ref']}", headers=h).json()["ref"] == r["ref"]
    assert c.get(f"/api/citizen/reports/{r['ref']}", headers=citizen(c)).status_code == 404
    assert c.get("/api/citizen/reports", headers=h).json()[0]["ref"] == r["ref"]


# 5. The same citizen reporting the same thing twice is marked duplicate and can't earn twice.
def test_duplicate_report(c):
    h = citizen(c)
    url = f"http://tamm-fines-{secrets.token_hex(2)}.top/pay"
    report(c, h, url)
    assert report(c, h, url)["status"] == "duplicate"


# 6. Corroboration by several distinct citizens raises priority but never blocks anything.
def test_corroboration_never_blocks(c):
    url = f"https://uaepass-verify-{secrets.token_hex(2)}.com/login"
    refs = [report(c, citizen(c), url) for _ in range(4)]
    tid = refs[0]["threat_refs"][0]
    t = c.get(f"/api/threats/{tid}", headers=admin(c)).json()
    assert t["status"] == "community_corroborated" and t["block_status"] == "none"
    assert c.get(f"/api/protection/check?value={url}").json()["blocked"] is False


# 7. Citizens have no way to block globally.
def test_citizen_cannot_block_globally(c):
    h = citizen(c)
    tid = report(c, h, f"http://adcb-secure-{secrets.token_hex(2)}.top/login")["threat_refs"][0]
    assert c.post(f"/api/threats/{tid}/block", json={}, headers=h).status_code == 403
    assert c.post("/api/antibody", json={"domain": "anything.top"}, headers=h).status_code == 403
    assert c.post("/api/protection/rollback", headers=h).status_code == 403


# 8. "Block for me" protects only that citizen.
def test_block_for_me_is_personal(c):
    a, b = citizen(c), citizen(c)
    c.post("/api/citizen/blocks", json={"value": "annoying-offers.example"}, headers=a)
    assert c.get("/api/protection/check?value=http://annoying-offers.example/", headers=a).json()["personal"] is True
    assert c.get("/api/protection/check?value=http://annoying-offers.example/", headers=b).json()["personal"] is False
    assert "annoying-offers.example" not in c.get("/api/blocklist.txt").text


# 9. Analysts verify, officials approve; global blocking needs approval permission and an approved threat.
def test_global_block_policy(c):
    adm, analyst = admin(c), official(c, "cyber_analyst")
    t = c.post("/api/threats", json={"indicator": f"http://etisalat-points-{secrets.token_hex(2)}.top/"}, headers=analyst).json()
    assert c.post(f"/api/threats/{t['id']}/block", json={}, headers=analyst).status_code == 403
    assert c.post(f"/api/threats/{t['id']}/block", json={}, headers=adm).status_code == 409  # not yet confirmed
    assert set_status(c, analyst, t["id"], "analyst_verified").status_code == 200
    assert set_status(c, analyst, t["id"], "confirmed_malicious").status_code == 403  # analysts verify, officials approve
    assert set_status(c, adm, t["id"], "confirmed_malicious").status_code == 200
    r = c.post(f"/api/threats/{t['id']}/block", json={"expiry_days": 14}, headers=adm)
    assert r.status_code == 200 and r.json()["threat"]["block_status"] == "global"


# 10. A threat on a shared platform or a popular domain is blocked at URL level, never the whole domain.
def test_url_level_blocking_for_shared_platforms(c):
    adm = admin(c)
    for url, expect_type in [("https://sites.google.com/view/uaepass-verify-acc", "url"),
                             ("https://my-tamm-portal.web.app/", "host")]:
        t = c.post("/api/threats", json={"indicator": url}, headers=adm).json()
        set_status(c, adm, t["id"], "confirmed_malicious")
        c.post(f"/api/threats/{t['id']}/block", json={}, headers=adm)
        rule = next(r for r in c.get("/api/protection/latest").json()["payload"]["rules"] if r["threat_id"] == t["id"])
        assert rule["type"] == expect_type
    assert c.get("/api/protection/check?value=https://sites.google.com/view/other-site").json()["blocked"] is False
    assert c.get("/api/protection/check?value=https://sites.google.com/view/uaepass-verify-acc").json()["blocked"] is True
    assert "sites.google.com" not in c.get("/api/blocklist.txt").text.split()


# 11. Protection packages are versioned and signed; any tampering is detected.
def test_signed_packages(c):
    pkg = c.get("/api/protection/latest").json()
    key = c.get("/api/protection/public-key").json()["public_key"]
    assert len(base64.b64decode(key)) == 32 and protection.verify(pkg, key)
    assert json.loads(pkg["signed_payload"]) == pkg["payload"]
    pkg["payload"]["rules"].append({"type": "domain", "value": "google.com"})
    assert not protection.verify(pkg, key)


# 12. An approver can roll back the latest protection version.
def test_rollback(c):
    adm = admin(c)
    t = c.post("/api/threats", json={"indicator": f"http://rollback-{secrets.token_hex(2)}.top/"}, headers=adm).json()
    set_status(c, adm, t["id"], "confirmed_malicious")
    v = c.post(f"/api/threats/{t['id']}/block", json={}, headers=adm).json()["version"]
    r = c.post("/api/protection/rollback", headers=adm).json()
    assert r["version"] == v + 1
    assert not any(x["threat_id"] == t["id"] for x in c.get("/api/protection/latest").json()["payload"]["rules"])
    assert c.get(f"/api/threats/{t['id']}", headers=adm).json()["block_status"] == "rolled_back"


# 13. Expired blocks leave the package and return to review.
def test_block_expiry(c):
    adm = admin(c)
    t = c.post("/api/threats", json={"indicator": f"http://expiry-{secrets.token_hex(2)}.top/"}, headers=adm).json()
    set_status(c, adm, t["id"], "confirmed_malicious")
    c.post(f"/api/threats/{t['id']}/block", json={"expiry_days": 1}, headers=adm)
    from raqeeb.db import db
    db().execute("UPDATE threats SET block_expires=1 WHERE id=?", (t["id"],))
    assert protection.expire_due() is not None
    t2 = c.get(f"/api/threats/{t['id']}", headers=adm).json()
    assert t2["block_status"] == "expired" and t2["status"] == "under_review"


# 14. Points are paid only after analyst verification, and only once.
def test_points_only_after_verification(c):
    h = citizen(c)
    r = report(c, h, f"https://emiratespost-redelivery-{secrets.token_hex(2)}.top/pay")
    assert c.get("/api/citizen/profile", headers=h).json()["points"] == 0
    adm = admin(c)
    tid = r["threat_refs"][0]
    set_status(c, adm, tid, "analyst_verified")
    p1 = c.get("/api/citizen/profile", headers=h).json()
    assert p1["points"] == 20 and p1["ledger"][0]["explanation"]
    set_status(c, adm, tid, "confirmed_malicious")
    assert c.get("/api/citizen/profile", headers=h).json()["points"] == 20


# 15. Points are reversed when a threat turns out to be a false positive; the reporter's weight drops.
def test_points_reversed_on_false_positive(c):
    h = citizen(c)
    tid = report(c, h, f"https://rta-nol-topup-{secrets.token_hex(2)}.top/")["threat_refs"][0]
    adm = admin(c)
    set_status(c, adm, tid, "analyst_verified")
    assert c.get("/api/citizen/profile", headers=h).json()["points"] > 0
    set_status(c, adm, tid, "false_positive")
    prof = c.get("/api/citizen/profile", headers=h).json()
    assert prof["points"] == 0 and prof["user"]["reputation"] < 1.0
    assert c.get(f"/api/citizen/reports", headers=h).json()[0]["status"] == "false_positive"


# 16. Leaderboards are anonymous by default, never expose emails, and respect opt-out.
def test_leaderboard_privacy(c):
    shown, hidden = citizen(c, "Sharjah"), citizen(c, "Sharjah", public=False)
    adm = admin(c)
    for h in (shown, hidden):
        tid = report(c, h, f"http://dewa-refund-{secrets.token_hex(2)}.top/")["threat_refs"][0]
        set_status(c, adm, tid, "analyst_verified")
    board = c.get("/api/public/leaderboard?period=week&emirate=Sharjah").json()["guardians"]
    assert len(board) == 1 and board[0]["display_name"].startswith("Guardian-")
    assert "@" not in json.dumps(board) and "id" not in board[0]


# 17. Levels follow the published thresholds.
def test_levels():
    from raqeeb.rewards import level
    assert level(0)["name"] == "Observer" and level(50)["name"] == "Scout" and level(5000)["name"] == "SAWNN Champion"
    assert level(149)["next"] == {"name": "Defender", "at": 150}


# 18. A link and a number seen in the same scam message are linked into one campaign.
def test_campaign_correlation(c):
    r = report(c, citizen(c), SCAM_SMS.format(n=18))
    g = c.get("/api/intel/graph", headers=admin(c)).json()
    camp = next(x for x in g["campaigns"] if r["threat_refs"][0] in x["threats"])
    assert set(r["threat_refs"]) <= set(camp["threats"]) and set(camp["types"]) == {"phone", "url"}


# 19. Forecasts are kept separate from confirmed threats and labelled as predictions.
def test_forecast_separates_evidence_classes(c):
    f = c.get("/api/intel/forecast", headers=admin(c)).json()
    assert {"confirmed_current", "observed_emerging", "predicted", "historical_associations"} <= set(f)
    assert "not confirmed" in f["note"]
    pub = c.get("/api/public/forecast").json()
    assert "confirmed_current" not in pub and pub["note"]


# 20. Security: SSRF targets refused, uploads validated, rate limits enforced, decisions audited.
def test_security_controls(c):
    for bad in ["http://127.0.0.1:8000/api/auth/me", "http://169.254.169.254/latest/meta-data", "http://10.0.0.5/",
                "http://localhost/", "ftp://example.com/", "http://example.com:22/"]:
        with pytest.raises(UnsafeTarget):
            check_url(bad)
    assert "Not fetched" in c.get("/api/preview?url=http://127.0.0.1:8000/").json().get("error", "")
    h = citizen(c)
    bad = c.post("/api/citizen/report", data={"text": ""}, files={"file": ("x.png", b"<?php system($_GET[1]); ?>", "image/png")}, headers=h)
    assert bad.status_code == 400
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (40, 20), "white").save(buf, "PNG")
    ok = c.post("/api/citizen/report", data={"text": "fake job offer asking for a visa fee", "type": "other"},
                files={"file": ("s.png", buf.getvalue(), "image/png")}, headers=h)
    assert ok.status_code == 200
    codes = [c.post("/api/auth/login", json={"email": "x@y.ae", "password": "nope-nope"}).status_code for _ in range(10)]
    assert 429 in codes
    assert any(a["action"] == "threat_status" for a in c.get("/api/audit", headers=admin(c)).json())
    assert c.get("/").headers["x-frame-options"] == "DENY" and "default-src 'self'" in c.get("/").headers["content-security-policy"]


# Full workflow: citizen report → AI analysis → corroboration → analyst verification → confirmation →
# approval → signed distribution → device check → citizen notified and rewarded.
def test_full_workflow(c):
    url = f"https://adpolice-fines-{secrets.token_hex(2)}.top/pay"
    first = citizen(c, "Abu Dhabi")
    r = report(c, first, f"Abu Dhabi Police: unpaid fine AED 400, 50% discount today only: {url}", "sms")
    tid = r["threat_refs"][0]
    for _ in range(3):
        report(c, citizen(c, "Dubai"), url, emirate="Dubai")
    adm, analyst = admin(c), official(c, "cyber_analyst")
    assert c.get(f"/api/threats/{tid}", headers=analyst).json()["status"] == "community_corroborated"
    assert set_status(c, analyst, tid, "analyst_verified").status_code == 200
    assert set_status(c, adm, tid, "confirmed_malicious").status_code == 200
    v = c.post(f"/api/threats/{tid}/block", json={"expiry_days": 30, "note": "fake fines portal"}, headers=adm).json()["version"]
    pkg = c.get("/api/protection/latest").json()
    assert pkg["payload"]["version"] == v and protection.verify(pkg)
    assert c.get(f"/api/check?url={url}").json()["blocked"] is True
    mine = c.get("/api/citizen/reports", headers=first).json()[0]
    assert mine["status"] == "confirmed_malicious"
    prof = c.get("/api/citizen/profile", headers=first).json()
    assert prof["points"] >= 15 and any(b["id"] == "first_verified" for b in prof["badges"])
    assert any("Confirmed" in n["title"] or "Analyst" in n["title"] for n in c.get("/api/citizen/notifications", headers=first).json())
    assert any(a["id"] == tid for a in c.get("/api/public/alerts").json())
    geo = {g["emirate"]: g for g in c.get("/api/intel/geography", headers=adm).json()}
    assert geo["Dubai"]["reports"] >= 3
