"""Assistant, phone and advert checkers, translation masking, report details, entry screen."""
import io
import secrets

import pytest
from fastapi.testclient import TestClient

from raqeeb.assistant import answer, detect_language
from raqeeb.messages import check_message
from raqeeb.security import limiter
from raqeeb.translate import mask, translate, unmask


@pytest.fixture(scope="module")
def c():
    from server.app import app
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _limits():
    limiter.reset()


def test_language_detection():
    assert detect_language("Someone from my bank called") == "en"
    assert detect_language("اتصل بي شخص من البنك") == "ar"
    assert detect_language("میرے بینک سے کال آئی") == "ur"
    assert detect_language("mujhe bank se call aayi kya karna hai") == "ur"


def test_assistant_uses_tools_and_answers_in_the_same_language():
    a = answer("هل هذا الرابط حقيقي https://uaepass-verify.com/login")
    assert a["language"] == "ar" and any(t["tool"] == "link_intelligence_engine" and t["verdict"] == "MALICIOUS" for t in a["tools"])
    assert a["live_intelligence"] and a["guidance"]
    u = answer("میرے بینک سے کال آئی اور او ٹی پی مانگا")
    assert u["language"] == "ur" and u["topic"] in ("otp", "bank_call") and not u["tools"]
    m = answer("I think I have already transferred money. What should I do?")
    assert m["urgent"] and any("bank" in g for g in m["guidance"])
    assert "not the police" in m["disclaimer"]


def test_urdu_scam_message_is_detected():
    r = check_message("آپ کا اکاؤنٹ بلاک ہو گیا ہے۔ فوری طور پر او ٹی پی بھیجیں")
    assert r["verdict"] == "scam" and {"otp", "blocked"} <= {s["code"] for s in r["script_signals"]}


def test_translation_never_changes_evidence(monkeypatch):
    text = "Pay AED 49 at https://tamm-camping-permit.top/pay?x=1 or call +971 50 000 0001, code 482193"
    masked, kept = mask(text)
    assert "https://" not in masked and "+971" not in masked and "482193" not in masked
    assert unmask(masked, kept) == text
    monkeypatch.delenv("SAWNN_LLM_URL", raising=False)
    assert translate(text, "ar")["available"] is False  # no model: say so, never guess


def test_phone_checker_never_condemns_on_reports_alone(c):
    r = c.get("/api/public/check-phone", params={"number": "050 123 4999"}).json()
    assert r["number"] == "+971501234999" and r["verdict"] == "unknown"
    h = {"Authorization": "Bearer " + c.post("/api/auth/register", json={"email": f"p{secrets.token_hex(3)}@example.ae", "password": "citizen-pass-1"}).json()["token"]}
    c.post("/api/citizen/report", data={"type": "phone", "text": "0501234999"}, headers=h)
    r = c.get("/api/public/check-phone", params={"number": "+971501234999"}).json()
    assert r["verdict"] == "reported" and r["reports"] >= 1 and "verify" in r["note"]
    assert c.get("/api/public/check-phone", params={"number": "hello"}).status_code == 400


def test_advert_checker(c):
    r = c.post("/api/public/check-ad", data={"text": "Water park family pass 80% OFF today only! Pay by bank transfer to reserve"}).json()
    assert r["verdict"] in ("scam", "suspicious") and r["signals"]
    from PIL import Image
    buf = io.BytesIO(); Image.new("RGB", (60, 30), "white").save(buf, "PNG")
    assert c.post("/api/public/check-ad", data={"text": "discount"}, files={"file": ("a.png", buf.getvalue(), "image/png")}).status_code == 200
    assert c.post("/api/public/check-ad", data={"text": ""}, files={"file": ("a.png", b"not an image", "image/png")}).status_code == 400


def test_report_details_can_be_added_later(c):
    h = {"Authorization": "Bearer " + c.post("/api/auth/register", json={"email": f"d{secrets.token_hex(3)}@example.ae", "password": "citizen-pass-1"}).json()["token"]}
    ref = c.post("/api/citizen/report", data={"type": "phone", "text": "Quick Alert: suspicious call. Caller claimed to be: My bank."}, headers=h).json()["ref"]
    assert c.post(f"/api/citizen/reports/{ref}/details", json={"text": "They also sent https://adcb-verify-now.top/login"}, headers=h).json()["details"] == 1
    other = {"Authorization": "Bearer " + c.post("/api/auth/register", json={"email": f"o{secrets.token_hex(3)}@example.ae", "password": "citizen-pass-1"}).json()["token"]}
    assert c.post(f"/api/citizen/reports/{ref}/details", json={"text": "x"}, headers=other).status_code == 404


def test_entry_screen_and_apps_are_served(c):
    assert "SAWNN Command" in c.get("/").text and "SAWNN Protect" in c.get("/").text and "sawnn-mark.png" in c.get("/").text
    assert c.get("/command").status_code == 200 and c.get("/app").status_code == 200
    assert c.get("/api/public/emergency").json()["ur"]
