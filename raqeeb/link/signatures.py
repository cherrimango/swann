"""Signature and reputation checks. Each adapter reports whether it ran, and every match carries its source,
the matching indicator, a timestamp, the source's own classification and a reference where one exists.

Always available (offline):
    raqeeb_published  - rules in MIRA's latest signed protection package (officially approved threats)
    raqeeb_threats    - threat records analysts verified or approved in MIRA
    public_feeds      - snapshot of OpenPhish + Phishing.Database bundled in models/ (refresh with data/download.py)
Optional, only when an API key is set in the environment (never invented when absent):
    google_web_risk   - GOOGLE_WEB_RISK_API_KEY
    virustotal        - VIRUSTOTAL_API_KEY
    urlhaus           - URLHAUS_AUTH_KEY
"""
import base64
import datetime as dt
import os
import time

import requests

from ..db import db, one
from ..engine import MODELS, threat_lists

TIMEOUT = 5
_cache: dict = {}
CACHE_SECONDS = 1800


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds")


def _cached(key, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


def _published(v):
    from ..protection import check_value
    r = check_value(v["normalised_url"])
    if not r:
        return []
    return [{"source": "raqeeb_published", "indicator": r["value"], "classification": "officially approved threat",
             "reference": r.get("threat_id"), "timestamp": _iso(time.time()), "rule_type": r["type"]}]


def _threats(v):
    host = v["hostname"].removeprefix("www.")
    t = one(db().execute("""SELECT id, status, last_seen, normalized FROM threats WHERE indicator_type IN ('url','domain','qr')
        AND status IN ('analyst_verified','confirmed_malicious') AND (normalized = ? OR normalized LIKE ?) ORDER BY status DESC LIMIT 1""",
                         (host, host + "/%")))
    if not t:
        return []
    label = "officially approved threat" if t["status"] == "confirmed_malicious" else "analyst-verified threat"
    return [{"source": "raqeeb_threats", "indicator": t["normalized"], "classification": label, "reference": t["id"],
             "timestamp": _iso(t["last_seen"])}]


def _feeds(v):
    hosts, urls = threat_lists()
    f = MODELS / "threat_hosts.txt.gz"
    snap = _iso(f.stat().st_mtime) if f.exists() else None
    host = v["hostname"].removeprefix("www.")
    out = []
    if v["normalised_url"].lower().rstrip("/") in urls or v["original_url"].strip().lower().rstrip("/") in urls:
        out.append({"source": "public_feeds", "indicator": v["normalised_url"], "classification": "phishing (exact URL)",
                    "reference": "OpenPhish / Phishing.Database", "timestamp": snap})
    elif host in hosts:
        out.append({"source": "public_feeds", "indicator": host, "classification": "phishing host",
                    "reference": "OpenPhish / Phishing.Database", "timestamp": snap})
    return out


def _web_risk(v, key):
    r = requests.get("https://webrisk.googleapis.com/v1/uris:search", timeout=TIMEOUT,
                     params=[("uri", v["normalised_url"]), ("threatTypes", "SOCIAL_ENGINEERING"), ("threatTypes", "MALWARE"), ("key", key)])
    r.raise_for_status()
    th = r.json().get("threat")
    return [{"source": "google_web_risk", "indicator": v["normalised_url"], "classification": ",".join(th.get("threatTypes", [])),
             "reference": None, "timestamp": th.get("expireTime")}] if th else []


def _virustotal(v, key):
    uid = base64.urlsafe_b64encode(v["normalised_url"].encode()).decode().strip("=")
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key}, timeout=TIMEOUT)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    if stats.get("malicious", 0) + stats.get("suspicious", 0) == 0:
        return []
    return [{"source": "virustotal", "indicator": v["normalised_url"],
             "classification": f"{stats.get('malicious', 0)} engines malicious, {stats.get('suspicious', 0)} suspicious",
             "reference": f"https://www.virustotal.com/gui/url/{uid}", "timestamp": _iso(a.get("last_analysis_date", time.time()))}]


def _urlhaus(v, key):
    r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": v["normalised_url"]}, headers={"Auth-Key": key}, timeout=TIMEOUT)
    r.raise_for_status()
    j = r.json()
    if j.get("query_status") != "ok":
        return []
    return [{"source": "urlhaus", "indicator": j.get("url"), "classification": j.get("threat") or "malware_download",
             "reference": j.get("urlhaus_reference"), "timestamp": j.get("date_added")}]


EXTERNAL = [("google_web_risk", "GOOGLE_WEB_RISK_API_KEY", _web_risk), ("virustotal", "VIRUSTOTAL_API_KEY", _virustotal),
            ("urlhaus", "URLHAUS_AUTH_KEY", _urlhaus)]


def _discovery(v):
    from ..discovery import SOURCES, lookup
    r = lookup(v["normalised_url"])
    if not r:
        return []
    return [{"source": "mira_discovery", "indicator": r["value"], "classification": "phishing (feed indicator, not yet analyst-verified)",
             "reference": SOURCES.get(r["source"], {}).get("name", r["source"]), "timestamp": _iso(r["last_seen"]),
             "first_seen": _iso(r["first_seen"]), "match_type": "exact URL", "reliability": "medium"}]


def check(v: dict, external: bool = True) -> dict:
    checked, matches, errors, skipped = [], [], {}, []
    for name, fn in (("raqeeb_published", _published), ("raqeeb_threats", _threats), ("public_feeds", _feeds), ("mira_discovery", _discovery)):
        try:
            matches += fn(v)
            checked.append(name)
        except Exception as e:  # noqa: BLE001
            errors[name] = str(e)[:160]
    for name, env, fn in EXTERNAL:
        key = os.environ.get(env)
        if not key or not external:
            skipped.append({"source": name, "reason": f"{env} not set" if not key else "quick scan"})
            continue
        try:
            matches += _cached((name, v["normalised_url"]), lambda: fn(v, key))
            checked.append(name)
        except Exception as e:  # noqa: BLE001 - a failed lookup is reported, never read as "clean"
            errors[name] = str(e)[:160]
    return {"known_threat": bool(matches), "sources_checked": checked, "sources_skipped": skipped, "errors": errors, "matches": matches}
