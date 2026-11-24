"""Database with versioned, additive migrations. Existing data is never dropped: each migration only adds."""
import os
import sqlite3
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("RAQEEB_DB", ROOT / "data" / "raqeeb.db"))
LOCK = threading.RLock()

MIGRATIONS = [
    # 1 — RAQEEB 1.0 schema (unchanged so existing databases keep working)
    """
    CREATE TABLE IF NOT EXISTS feed (id INTEGER PRIMARY KEY, url TEXT UNIQUE, host TEXT, brand TEXT, risk REAL,
        verdict TEXT, source TEXT, reason TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, kind TEXT, content TEXT, verdict TEXT, risk REAL,
        brand TEXT, emirate TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY, reason TEXT, brand TEXT, added_by TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT, detail TEXT, ts REAL);
    """,
    # 2 — RAQEEB 2.0: accounts, threat intelligence, community, rewards, protection distribution
    """
    ALTER TABLE audit ADD COLUMN actor TEXT;
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL,
        display_name TEXT NOT NULL, emirate TEXT, public_rank INTEGER NOT NULL DEFAULT 1, reputation REAL NOT NULL DEFAULT 1.0,
        disabled INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
    CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL, expires REAL, ip TEXT);
    CREATE TABLE threats (id TEXT PRIMARY KEY, category TEXT NOT NULL, indicator_type TEXT NOT NULL, original TEXT,
        normalized TEXT NOT NULL, brand TEXT, first_seen REAL, last_seen REAL, report_count INTEGER NOT NULL DEFAULT 0,
        ai_confidence REAL, risk REAL, status TEXT NOT NULL, severity TEXT, campaign_id TEXT, evidence TEXT, history TEXT,
        block_status TEXT NOT NULL DEFAULT 'none', block_scope TEXT, block_expires REAL, emirates TEXT, reviewer TEXT,
        source TEXT, UNIQUE (indicator_type, normalized));
    CREATE INDEX idx_threats_status ON threats(status);
    CREATE TABLE citizen_reports (id INTEGER PRIMARY KEY, ref TEXT UNIQUE, user_id INTEGER, type TEXT, raw_text TEXT,
        indicators TEXT, attachment TEXT, emirate TEXT, impact TEXT, status TEXT NOT NULL, threat_ids TEXT, ai TEXT,
        duplicate_of TEXT, ip_hash TEXT, created REAL, updated REAL);
    CREATE TABLE corroborations (threat_id TEXT, user_id INTEGER, report_id INTEGER, weight REAL, created REAL,
        PRIMARY KEY (threat_id, user_id));
    CREATE TABLE points (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, delta INTEGER NOT NULL, reason TEXT NOT NULL,
        threat_id TEXT, report_id INTEGER, kind TEXT NOT NULL DEFAULT 'verified', explanation TEXT, created REAL,
        UNIQUE (user_id, reason, threat_id));
    CREATE TABLE badges (user_id INTEGER, badge TEXT, created REAL, PRIMARY KEY (user_id, badge));
    CREATE TABLE personal_blocks (user_id INTEGER, value TEXT, kind TEXT, created REAL, PRIMARY KEY (user_id, value));
    CREATE TABLE protection_versions (version INTEGER PRIMARY KEY, created REAL, published_by TEXT, rules TEXT,
        signature TEXT, notes TEXT, rolled_back INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE findings (id INTEGER PRIMARY KEY, agent TEXT, subject TEXT, confidence REAL, evidence TEXT,
        reasoning TEXT, source TEXT, next_action TEXT, created REAL);
    CREATE TABLE investigation_notes (id INTEGER PRIMARY KEY, threat_id TEXT, author TEXT, note TEXT, created REAL);
    CREATE TABLE families (id INTEGER PRIMARY KEY, name TEXT, code TEXT UNIQUE, owner INTEGER, created REAL);
    CREATE TABLE family_members (family_id INTEGER, user_id INTEGER, PRIMARY KEY (family_id, user_id));
    CREATE TABLE notifications (id INTEGER PRIMARY KEY, user_id INTEGER, audience TEXT, kind TEXT, title TEXT,
        body TEXT, data TEXT, created REAL);
    CREATE TABLE learning (user_id INTEGER, sim_id TEXT, correct INTEGER, created REAL, PRIMARY KEY (user_id, sim_id));
    """,
    # 3 — counters for impact reporting
    """
    CREATE TABLE metrics (key TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX idx_reports_user ON citizen_reports(user_id);
    CREATE INDEX idx_points_user ON points(user_id);
    """,
]


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def migrate(c: sqlite3.Connection) -> int:
    c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = c.execute("SELECT version FROM schema_version").fetchone()
    current = row[0] if row else 0
    if not row:
        c.execute("INSERT INTO schema_version (version) VALUES (0)")
    for i, script in enumerate(MIGRATIONS, start=1):
        if i <= current:
            continue
        c.execute("BEGIN")
        try:
            for stmt in [s.strip() for s in script.split(";") if s.strip()]:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError as e:  # column/table already there from a 1.0 database
                    if "duplicate column" not in str(e) and "already exists" not in str(e):
                        raise
            c.execute("UPDATE schema_version SET version = ?", (i,))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    return len(MIGRATIONS)


_conn = None


def db() -> sqlite3.Connection:
    global _conn
    with LOCK:
        if _conn is None:
            _conn = _connect()
            migrate(_conn)
        return _conn


def reset_for_tests(path: Path):
    """Point the module at a fresh database file (tests only)."""
    global _conn, DB_PATH
    with LOCK:
        if _conn is not None:
            _conn.close()
        _conn, DB_PATH = None, Path(path)


def rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def one(cur):
    r = cur.fetchone()
    return dict(r) if r else None
