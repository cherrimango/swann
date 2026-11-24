"""Behavioural checks for the rule layer. Run: pytest -q"""
import pytest

from raqeeb.engine import scan

OFFICIAL = ["https://www.tamm.abudhabi/", "https://uaepass.ae/login", "https://www.adpolice.gov.ae/en/",
            "https://smartservices.icp.gov.ae/echannels/web/client/default.html", "https://www.adcb.com/en/personal/",
            "https://www.emiratespost.ae/", "https://www.salik.ae/en"]
IMPERSONATION = ["https://uaepass-reactivate.com/login", "https://tamm.abudhabi.gov-ae.top/",
                 "https://adpolice-fines.web.app/", "https://sallk-ae.com/recharge", "https://xn--uaepss-6nf.com/login",
                 "https://emiratespost.ae.track-parcel.icu/", "https://sites.google.com/view/uaepass-verify-account"]
NOT_IMPERSONATION = ["https://www.google.com/search?q=tamm", "https://www.khaleejtimes.com/uae/tamm-new-service",
                     "https://amazon.ae", "https://ikea.ae"]


@pytest.mark.parametrize("url", OFFICIAL)
def test_official_domains_are_safe(url):
    assert scan(url)["verdict"] == "safe"


@pytest.mark.parametrize("url", IMPERSONATION)
def test_impersonation_is_flagged_with_brand(url):
    r = scan(url)
    assert r["label"] == 1 and r["impersonated_brand"] is not None


@pytest.mark.parametrize("url", NOT_IMPERSONATION)
def test_brand_mentions_on_legit_sites_are_not_flagged(url):
    assert scan(url)["label"] == 0


def test_shortener_is_suspicious_not_phishing():
    assert scan("https://bit.ly/3xYz")["verdict"] == "suspicious"


def test_every_flag_has_bilingual_reasons():
    r = scan("http://tamm-abudhabi-fines.top/pay")
    assert r["reasons"] and all(x["en"] and x["ar"] for x in r["reasons"])
