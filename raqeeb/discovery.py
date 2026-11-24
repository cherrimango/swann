"""SAWNN Global Threat Discovery Engine: scheduled, incremental collection from permitted public threat feeds.

Only sources whose terms allow automated download are polled, at their documented update interval or slower. There is
no indiscriminate crawling. Each run is recorded (start, finish, status, collected, new, duplicates, error) so source
health is visible in Command. New indicators are stored as UNVERIFIED leads: they feed signature matching for deep
scans and analyst review, and never trigger a global block on their own.

Scheduling: start_scheduler() runs inside the server when SAWNN_DISCOVERY_ENABLED=1, every SAWNN_DISCOVERY_INTERVAL_MIN
minutes (default 60). Command administrators can also run a collection now. Times are stored in UTC epoch seconds.
"""
import os
import threading
import time

from .db import db, one, rows
from .security import UnsafeTarget, safe_get
from .urlparse import parse

SOURCES = {
    "openphish": {"name": "OpenPhish community feed", "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
                  "format": "lines", "key_env": None, "terms": "OpenPhish community feed, non-commercial", "min_interval_min": 60},
    "phishing_database_hour": {"name": "Phishing.Database — new links, last hour",
                               "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-last-hour.txt",
                               "format": "lines", "key_env": None, "terms": "MIT licence", "min_interval_min": 15},
    "phishing_database_today": {"name": "Phishing.Database — new links today",
                                "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
                                "format": "lines", "key_env": None, "terms": "MIT licence", "min_interval_min": 60},
    "urlhaus_recent": {"name": "URLhaus recent URLs (abuse.ch)", "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                       "format": "urlhaus_json", "key_env": "SAWNN_URLHAUS_AUTH_KEY", "key_header": "Auth-Key",
                       "terms": "abuse.ch terms of use; free Auth-Key required since 30 June 2025", "min_interval_min": 5},
    "phishtank": {"name": "PhishTank online-valid", "url": "https://data.phishtank.com/data/{key}/online-valid.csv",
                  "format": "phishtank_csv", "key_env": "SAWNN_PHISHTANK_APP_KEY", "terms": "PhishTank developer terms (free key)",
                  "min_interval_min": 60},
}
_lock = threading.Lock()
_sched = {"thread": None, "interval_min": None, "next_run": None}


def _parse_lines(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and line.lower().startswith(("http://", "https://")):
            out.append(line[:2000])
    return out


def _parse_phishtank(text):
    import csv
    import io
    return [r["url"][:2000] for r in csv.DictReader(io.StringIO(text)) if r.get("url")]


def _parse_urlhaus(text):
    import json
    return [u["url"][:2000] for u in json.loads(text).get("urls", []) if u.get("url")]


def collect(source_id: str) -> dict:
    src = SOURCES[source_id]
    started = time.time()
    rec = {"source": source_id, "started": started, "collected": 0, "new_indicators": 0, "duplicates": 0, "error": None}
    key = os.environ.get(src["key_env"]) if src["key_env"] else None
    if src["key_env"] and not key:
        rec.update(status="blocked_missing_key", error=f"set {src['key_env']} to enable this source")
    else:
        try:
            headers = {src["key_header"]: key} if src.get("key_header") and key else None
            url = src["url"].format(key=key or "")
            _, _, body = safe_get(url, headers=headers, timeout=20) if headers else safe_get(url, timeout=20)
            urls = {"phishtank_csv": _parse_phishtank, "urlhaus_json": _parse_urlhaus}.get(src["format"], _parse_lines)(body)
            now = time.time()
            with _lock:
                for u in urls:
                    p = parse(u)
                    if not p.host:
                        continue
                    val = p.url.lower().rstrip("/")
                    cur = db().execute("UPDATE indicators SET last_seen=?, times_seen=times_seen+1 WHERE value=?", (now, val))
                    if cur.rowcount:
                        rec["duplicates"] += 1
                    else:
                        db().execute("INSERT INTO indicators (value, kind, source, first_seen, last_seen, registered_domain) VALUES (?,?,?,?,?,?)",
                                     (val, "url", source_id, now, now, p.registered_domain))
                        rec["new_indicators"] += 1
                rec["collected"] = len(urls)
                db().commit()
            rec["status"] = "ok"
        except UnsafeTarget as e:
            rec.update(status="failed", error=f"blocked by SSRF guard: {e}")
        except Exception as e:  # noqa: BLE001 - network or parsing failure is recorded, never hidden
            rec.update(status="failed", error=str(e).splitlines()[0][:240] if str(e) else e.__class__.__name__)
    rec["finished"] = time.time()
    db().execute("""INSERT INTO discovery_runs (source, started, finished, status, collected, new_indicators, duplicates, error)
        VALUES (?,?,?,?,?,?,?,?)""", (source_id, rec["started"], rec["finished"], rec["status"], rec["collected"],
                                      rec["new_indicators"], rec["duplicates"], rec["error"]))
    db().commit()
    return rec


def run_all() -> list[dict]:
    return [collect(s) for s in SOURCES]


def status() -> dict:
    out = []
    for sid, s in SOURCES.items():
        last = one(db().execute("SELECT * FROM discovery_runs WHERE source=? ORDER BY id DESC LIMIT 1", (sid,)))
        ok = one(db().execute("SELECT finished FROM discovery_runs WHERE source=? AND status='ok' ORDER BY id DESC LIMIT 1", (sid,)))
        total = db().execute("SELECT COUNT(*) FROM indicators WHERE source=?", (sid,)).fetchone()[0]
        out.append({"id": sid, "name": s["name"], "terms": s["terms"], "requires_key": s["key_env"],
                    "key_configured": bool(os.environ.get(s["key_env"])) if s["key_env"] else None,
                    "last_run": last, "last_success": ok["finished"] if ok else None, "indicators_stored": total,
                    "health": "never run" if not last else ("healthy" if last["status"] == "ok" else last["status"])})
    totals = one(db().execute("""SELECT COUNT(*) total, SUM(verified) verified,
        SUM(CASE WHEN first_seen > ? THEN 1 ELSE 0 END) new_24h FROM indicators""", (time.time() - 86400,)))
    from .orchestrator import scheduler_status
    sch = scheduler_status()
    proc = {r["status"]: r["n"] for r in rows(db().execute("SELECT status, COUNT(*) n FROM indicators GROUP BY status"))}
    verd = {r["verdict"]: r["n"] for r in rows(db().execute("SELECT verdict, COUNT(*) n FROM indicators WHERE verdict IS NOT NULL GROUP BY verdict"))}
    lat = one(db().execute("SELECT AVG(processed - first_seen) a FROM indicators WHERE processed IS NOT NULL"))
    doms = one(db().execute("SELECT COUNT(DISTINCT registered_domain) n FROM indicators WHERE first_seen > ?", (time.time() - 86400,)))
    threats = db().execute("SELECT COUNT(*) FROM indicators WHERE threat_id IS NOT NULL").fetchone()[0]
    return {"sources": out, "scheduler": sch, "processing": {"by_status": proc, "by_verdict": verd,
            "avg_latency_s": round(lat["a"], 1) if lat and lat["a"] is not None else None, "new_domains_24h": doms["n"] if doms else 0,
            "investigations_created": threats},
            "indicators": {"total": totals["total"] or 0, "verified": totals["verified"] or 0,
                           "unverified": (totals["total"] or 0) - (totals["verified"] or 0), "new_24h": totals["new_24h"] or 0},
            "recent_runs": rows(db().execute("SELECT * FROM discovery_runs ORDER BY id DESC LIMIT 30")),
            "note": "Indicators from feeds are unverified leads. Times are UTC epoch seconds; the interface shows local time."}


def lookup(url_or_host: str) -> dict | None:
    p = parse(url_or_host)
    val = p.url.lower().rstrip("/")
    return one(db().execute("SELECT * FROM indicators WHERE value = ? OR value = ? LIMIT 1", (val, "http://" + p.host)))


def health_check() -> dict:
    """Lightweight reachability check of every source (no ingestion)."""
    import requests
    out = []
    for sid, src in SOURCES.items():
        key = os.environ.get(src["key_env"]) if src["key_env"] else None
        if src["key_env"] and not key:
            out.append({"source": sid, "status": "blocked_missing_key", "error": f"set {src['key_env']}"})
            continue
        t0 = time.time()
        try:
            from .security import check_url
            url = src["url"].format(key=key or "")
            check_url(url)
            r = requests.head(url, timeout=6, allow_redirects=False, headers={src["key_header"]: key} if src.get("key_header") and key else {})
            out.append({"source": sid, "status": "ok" if r.status_code < 400 or r.status_code == 405 else "failed",
                        "http_status": r.status_code, "ms": round((time.time() - t0) * 1000), "error": None if r.status_code < 400 or r.status_code == 405 else f"HTTP {r.status_code}"})
        except Exception as e:  # noqa: BLE001
            out.append({"source": sid, "status": "failed", "error": str(e).splitlines()[0][:200] if str(e) else e.__class__.__name__})
    return {"runs": out}


def start_scheduler():
    """Kept for compatibility: the SAWNN orchestrator scheduler now runs all monitoring jobs."""
    from .orchestrator import start_scheduler as s
    s()
