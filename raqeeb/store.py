"""SQLite store for the command centre: hunt feed, resident reports, blocklist (antibodies) and audit log."""
import json
import sqlite3
import threading
import time
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "raqeeb.db"
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS feed (id INTEGER PRIMARY KEY, url TEXT UNIQUE, host TEXT, brand TEXT, risk REAL,
    verdict TEXT, source TEXT, reason TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, kind TEXT, content TEXT, verdict TEXT, risk REAL,
    brand TEXT, emirate TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY, reason TEXT, brand TEXT, added_by TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT, detail TEXT, ts REAL);
"""


def conn():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


_c = None


def db():
    global _c
    if _c is None:
        _c = conn()
        _c.executescript(SCHEMA)
    return _c


def _rows(cur):
    return [dict(r) for r in cur.fetchall()]


def add_feed(url, host, brand, risk, verdict, source, reason, ts=None):
    with _lock:
        db().execute("INSERT OR IGNORE INTO feed (url,host,brand,risk,verdict,source,reason,ts) VALUES (?,?,?,?,?,?,?,?)",
                     (url, host, brand, risk, verdict, source, reason, time.time() if ts is None else ts))
        db().commit()


def feed(limit=200, brand=None):
    q, args = "SELECT * FROM feed", []
    if brand:
        q += " WHERE brand = ?"
        args.append(brand)
    q += " ORDER BY ts DESC, risk DESC LIMIT ?"
    args.append(limit)
    return _rows(db().execute(q, args))


def add_report(kind, content, verdict, risk, brand, emirate):
    with _lock:
        cur = db().execute("INSERT INTO reports (kind,content,verdict,risk,brand,emirate,ts) VALUES (?,?,?,?,?,?,?)",
                           (kind, content[:2000], verdict, risk, brand, emirate, time.time()))
        db().commit()
        return cur.lastrowid


def reports(limit=200):
    return _rows(db().execute("SELECT * FROM reports ORDER BY ts DESC LIMIT ?", (limit,)))


def block(domain, reason, brand, added_by):
    with _lock:
        db().execute("INSERT OR REPLACE INTO blocklist (domain,reason,brand,added_by,ts) VALUES (?,?,?,?,?)",
                     (domain.lower(), reason, brand, added_by, time.time()))
        db().execute("INSERT INTO audit (action,detail,ts) VALUES (?,?,?)",
                     ("block", json.dumps({"domain": domain, "by": added_by}), time.time()))
        db().commit()


def unblock(domain, by):
    with _lock:
        db().execute("DELETE FROM blocklist WHERE domain = ?", (domain.lower(),))
        db().execute("INSERT INTO audit (action,detail,ts) VALUES (?,?,?)",
                     ("unblock", json.dumps({"domain": domain, "by": by}), time.time()))
        db().commit()


def blocklist():
    return _rows(db().execute("SELECT * FROM blocklist ORDER BY ts DESC"))


def is_blocked(host):
    host = host.lower()
    parts = host.split(".")
    cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    q = "SELECT domain FROM blocklist WHERE domain IN (%s)" % ",".join("?" * len(cands))
    return bool(cands) and db().execute(q, cands).fetchone() is not None


def stats():
    d = db()
    one = lambda q: d.execute(q).fetchone()[0]  # noqa: E731
    return {
        "feed_total": one("SELECT COUNT(*) FROM feed"),
        "feed_phishing": one("SELECT COUNT(*) FROM feed WHERE verdict='phishing'"),
        "reports": one("SELECT COUNT(*) FROM reports"),
        "blocked": one("SELECT COUNT(*) FROM blocklist"),
        "by_brand": _rows(d.execute("SELECT brand, COUNT(*) n FROM feed WHERE brand != '' GROUP BY brand ORDER BY n DESC LIMIT 12")),
        "reports_by_emirate": _rows(d.execute("SELECT emirate, COUNT(*) n FROM reports GROUP BY emirate ORDER BY n DESC")),
    }
