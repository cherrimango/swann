"""MIRA Global Threat Discovery Engine: scheduled, incremental collection from permitted public threat feeds.

Only sources whose terms allow automated download are polled, at their documented update interval or slower. There is
no indiscriminate crawling. Each run is recorded (start, finish, status, collected, new, duplicates, error) so source
health is visible in Command. New indicators are stored as UNVERIFIED leads: they feed signature matching for deep
scans and analyst review, and never trigger a global block on their own.

Scheduling: start_scheduler() runs inside the server when MIRA_DISCOVERY_ENABLED=1, every MIRA_DISCOVERY_INTERVAL_MIN
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
    "phishing_database_today": {"name": "Phishing.Database — new links today",
                                "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
                                "format": "lines", "key_env": None, "terms": "MIT licence", "min_interval_min": 60},
    "urlhaus_recent": {"name": "URLhaus recent URLs (abuse.ch)", "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
                       "format": "lines", "key_env": None, "terms": "abuse.ch terms of use (CC0 data)", "min_interval_min": 5},
    "phishtank": {"name": "PhishTank online-valid", "url": "https://data.phishtank.com/data/{key}/online-valid.csv",
                  "format": "phishtank_csv", "key_env": "MIRA_PHISHTANK_APP_KEY", "terms": "PhishTank developer terms (free key)",
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


def collect(source_id: str) -> dict:
    src = SOURCES[source_id]
    started = time.time()
    rec = {"source": source_id, "started": started, "collected": 0, "new_indicators": 0, "duplicates": 0, "error": None}
    key = os.environ.get(src["key_env"]) if src["key_env"] else None
    if src["key_env"] and not key:
        rec.update(status="blocked_missing_key", error=f"set {src['key_env']} to enable this source")
    else:
        try:
            _, _, body = safe_get(src["url"].format(key=key or ""), timeout=20)
            urls = _parse_phishtank(body) if src["format"] == "phishtank_csv" else _parse_lines(body)
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
                        db().execute("INSERT INTO indicators (value, kind, source, first_seen, last_seen) VALUES (?,?,?,?,?)",
                                     (val, "url", source_id, now, now))
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
    return {"sources": out, "scheduler": {"enabled": os.environ.get("MIRA_DISCOVERY_ENABLED") == "1",
                                          "interval_min": _sched["interval_min"], "next_run": _sched["next_run"],
                                          "running": bool(_sched["thread"] and _sched["thread"].is_alive())},
            "indicators": {"total": totals["total"] or 0, "verified": totals["verified"] or 0,
                           "unverified": (totals["total"] or 0) - (totals["verified"] or 0), "new_24h": totals["new_24h"] or 0},
            "recent_runs": rows(db().execute("SELECT * FROM discovery_runs ORDER BY id DESC LIMIT 30")),
            "note": "Indicators from feeds are unverified leads. Times are UTC epoch seconds; the interface shows local time."}


def lookup(url_or_host: str) -> dict | None:
    p = parse(url_or_host)
    val = p.url.lower().rstrip("/")
    return one(db().execute("SELECT * FROM indicators WHERE value = ? OR value = ? LIMIT 1", (val, "http://" + p.host)))


def start_scheduler():
    if os.environ.get("MIRA_DISCOVERY_ENABLED") != "1" or (_sched["thread"] and _sched["thread"].is_alive()):
        return
    interval = max(15, int(os.environ.get("MIRA_DISCOVERY_INTERVAL_MIN", "60")))
    _sched["interval_min"] = interval

    def loop():
        while True:
            try:
                run_all()
            except Exception:  # noqa: BLE001 - keep the scheduler alive; failures are in discovery_runs
                pass
            _sched["next_run"] = time.time() + interval * 60
            time.sleep(interval * 60)
    _sched["thread"] = threading.Thread(target=loop, daemon=True, name="mira-discovery")
    _sched["thread"].start()
