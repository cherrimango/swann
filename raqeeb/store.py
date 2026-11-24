"""SQLite store for the command centre: hunt feed, resident reports, blocklist (antibodies) and audit log."""
import json
import threading
import time

_lock = threading.Lock()


def db():
    """Shared connection from raqeeb.db (runs migrations on first use)."""
    from .db import db as _db
    return _db()


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
        db().execute("INSERT INTO audit (action,detail,ts,actor) VALUES (?,?,?,?)",
                     ("block", json.dumps({"domain": domain}), time.time(), added_by))
        db().commit()


def unblock(domain, by):
    with _lock:
        db().execute("DELETE FROM blocklist WHERE domain = ?", (domain.lower(),))
        db().execute("INSERT INTO audit (action,detail,ts,actor) VALUES (?,?,?,?)",
                     ("unblock", json.dumps({"domain": domain}), time.time(), by))
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
