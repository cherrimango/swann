"""Demo mode: the seeded winter-camping scenario runs through the real workflow and can be removed again."""
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


def test_demo_off_by_default(monkeypatch):
    monkeypatch.delenv("SAWNN_DEMO", raising=False)
    from server.app import app
    with TestClient(app) as client:
        assert client.get("/api/public/demo").json() == {"enabled": False, "accounts": [], "note": "Demonstration-only accounts. Never reuse these passwords."}


def test_winter_camping_scenario_end_to_end(c):
    from raqeeb.demo_scenario import SCENARIO
    accounts = c.get("/api/public/demo").json()["accounts"]
    assert {a["email"] for a in accounts} == {"admin@sawnn.demo", "analyst@sawnn.demo", "citizen@sawnn.demo"}
    adm, ana = tok(c, "admin@sawnn.demo", "SawnnDemo2026!"), tok(c, "analyst@sawnn.demo", "AnalystDemo2026!")
    cit = tok(c, "citizen@sawnn.demo", "CitizenDemo2026!")
    assert c.post("/api/demo/seed", headers=ana).status_code == 403  # analysts can't run the seed (it creates records)
    st = c.post("/api/demo/seed", headers=adm).json()["status"]
    tid = st["threat_id"]
    assert all(s["done"] for s in st["steps"][:5]) and not any(s["done"] for s in st["steps"][5:])
    t = c.get(f"/api/threats/{tid}", headers=ana).json()
    assert t["demo"] == 1 and "DEMO SEED" in t["source"]
    assert c.post(f"/api/threats/{tid}/status", json={"status": "analyst_verified"}, headers=ana).status_code == 200
    assert c.post(f"/api/threats/{tid}/status", json={"status": "confirmed_malicious"}, headers=ana).status_code == 403
    assert c.post(f"/api/threats/{tid}/status", json={"status": "confirmed_malicious"}, headers=adm).status_code == 200
    assert c.post(f"/api/threats/{tid}/block", json={}, headers=adm).status_code == 200
    assert c.get("/api/check", params={"url": SCENARIO["payment_link"]}).json()["blocked"] is True
    rep = c.post("/api/citizen/report", data={"type": "ad", "text": SCENARIO["ad_text"], "emirate": "Abu Dhabi"}, headers=cit).json()
    for x in rep["threat_refs"]:
        c.post(f"/api/threats/{x}/status", json={"status": "analyst_verified"}, headers=ana)
    prof = c.get("/api/citizen/profile", headers=cit).json()
    assert prof["points"] > 0 and any(l["reason"] == "campaign_connection" for l in prof["ledger"])
    assert all(s["done"] for s in c.get("/api/demo/status", headers=adm).json()["steps"])
    assert c.post("/api/demo/reset", headers=adm).json()["removed_threats"] >= 4
    assert c.get("/api/demo/status", headers=adm).json()["threat_id"] is None
    assert c.get("/api/check", params={"url": SCENARIO["payment_link"]}).json()["blocked"] is False
