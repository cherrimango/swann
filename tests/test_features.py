"""Message checker, twin view, Scam DNA campaigns and API. Run: pytest -q"""
from fastapi.testclient import TestClient

from raqeeb.campaigns import build, kit_signature
from raqeeb.messages import check_message
from raqeeb.twin import twin


def test_darb_toll_sms_is_a_scam():
    r = check_message("Darb-Alert: settle overdue toll fees (AED4.00) today to avoid a AED100 fine. Reply Y to open darb-toll-pay.top/pay")
    assert r["verdict"] == "scam" and {"small_fee", "fine_toll", "reply_y"} <= {h["code"] for h in r["script_signals"]}


def test_arabic_bank_sms_is_a_scam():
    r = check_message("عزيزي العميل، تم إيقاف بطاقتك. يرجى تحديث بياناتك خلال 24 ساعة عبر الرابط adcb-update-kyc.net")
    assert r["verdict"] == "scam" and r["advice_ar"]


def test_normal_message_is_safe():
    assert check_message("Dinner at 8? I booked the usual place.")["verdict"] == "looks safe"


def test_twin_flags_cyrillic_letter():
    t = twin("https://xn--uaepss-6nf.com/login", ["uaepass.ae"])
    assert t["official"] == "uaepass.ae" and t["unicode_tricks"][0]["codepoint"] == "U+0430"


def test_same_kit_on_two_domains_is_one_campaign():
    rows = [{"url": "http://a-site.com/x/aramex/clients/cc.php", "registered_domain": "a-site.com", "brand": "Aramex"},
            {"url": "http://b-site.be/aramex/delivery/clients/cc.php", "registered_domain": "b-site.be", "brand": "Aramex"}]
    assert kit_signature(rows[0]["url"]) == "/clients/cc.php"
    assert len(build(rows)["campaigns"]) == 1


def test_antibody_reaches_blocklist_and_phones():
    from server.app import app
    with TestClient(app) as c, c.websocket_connect("/ws") as ws:
        c.post("/api/antibody", json={"domain": "test-scam-domain.top", "brand": "Test", "reason": "test"})
        assert '"antibody"' in ws.receive_text()
        assert "test-scam-domain.top" in c.get("/api/blocklist.txt").text
        assert c.get("/api/check?url=http://test-scam-domain.top/pay").json()["blocked"] is True
        c.delete("/api/antibody/test-scam-domain.top")
