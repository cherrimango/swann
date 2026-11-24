"""Database with versioned, additive migrations. Existing data is never dropped: each migration only adds."""
import os
import sqlite3
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("SAWNN_DB", ROOT / "data" / "raqeeb.db"))
LOCK = threading.RLock()

MIGRATIONS = [
    # 1 — SAWNN 1.0 schema (unchanged so existing databases keep working)
    """
    CREATE TABLE IF NOT EXISTS feed (id INTEGER PRIMARY KEY, url TEXT UNIQUE, host TEXT, brand TEXT, risk REAL,
        verdict TEXT, source TEXT, reason TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY, kind TEXT, content TEXT, verdict TEXT, risk REAL,
        brand TEXT, emirate TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS blocklist (domain TEXT PRIMARY KEY, reason TEXT, brand TEXT, added_by TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT, detail TEXT, ts REAL);
    """,
    # 2 — SAWNN 2.0: accounts, threat intelligence, community, rewards, protection distribution
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
    # 4 — Link Intelligence Engine scans and the organisation registry
    """
    CREATE TABLE scans (id TEXT PRIMARY KEY, url TEXT, verdict TEXT, risk_score REAL, mode TEXT, status TEXT NOT NULL,
        report TEXT, user_id INTEGER, created REAL);
    CREATE INDEX idx_scans_user ON scans(user_id);
    CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, name_ar TEXT, sector TEXT, domains TEXT NOT NULL,
        keywords TEXT, added_by TEXT, created REAL);
    ALTER TABLE threats ADD COLUMN demo INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE citizen_reports ADD COLUMN details TEXT;
    """,
    # 5 — SAWNN: citizen-alert workflow, attachment analysis, threat discovery engine
    """
    CREATE TABLE citizen_alerts (id TEXT PRIMARY KEY, status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
        severity TEXT NOT NULL, category TEXT NOT NULL, audience TEXT NOT NULL, channels TEXT NOT NULL, content TEXT NOT NULL,
        brands TEXT, threat_ids TEXT, expires REAL, ai_drafted INTEGER NOT NULL DEFAULT 0, demo INTEGER NOT NULL DEFAULT 0,
        created_by TEXT, created REAL, reviewed_by TEXT, reviewed REAL, review_note TEXT, approved_by TEXT, approved REAL,
        published_by TEXT, published REAL, withdrawn_by TEXT, withdrawn REAL);
    CREATE TABLE citizen_alert_versions (alert_id TEXT, version INTEGER, content TEXT, edited_by TEXT, edited REAL,
        PRIMARY KEY (alert_id, version));
    CREATE TABLE alert_deliveries (id INTEGER PRIMARY KEY, alert_id TEXT, channel TEXT, status TEXT, recipients INTEGER,
        detail TEXT, created REAL);
    CREATE TABLE alert_engagement (alert_id TEXT, user_id INTEGER, action TEXT, created REAL, PRIMARY KEY (alert_id, user_id, action));
    CREATE TABLE alert_subscriptions (user_id INTEGER, category TEXT, PRIMARY KEY (user_id, category));
    CREATE TABLE attachments (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, kind TEXT, size INTEGER, report TEXT, user_id INTEGER, created REAL);
    CREATE TABLE discovery_runs (id INTEGER PRIMARY KEY, source TEXT NOT NULL, started REAL, finished REAL, status TEXT,
        collected INTEGER, new_indicators INTEGER, duplicates INTEGER, error TEXT);
    CREATE TABLE indicators (value TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, first_seen REAL, last_seen REAL,
        times_seen INTEGER NOT NULL DEFAULT 1, verified INTEGER NOT NULL DEFAULT 0, brand TEXT);
    CREATE INDEX idx_indicators_last ON indicators(last_seen);
    """,
    # 6 — SAWNN: agent orchestration, scheduler, discovery processing, model evaluations
    """
    CREATE TABLE agent_tasks (id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL, parent_id TEXT, agent TEXT NOT NULL, status TEXT NOT NULL,
        input TEXT, input_refs TEXT, created REAL, started REAL, finished REAL, duration_ms REAL, findings TEXT, evidence TEXT,
        confidence REAL, sources TEXT, errors TEXT, recommended_action TEXT, handoffs TEXT, depth INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX idx_tasks_status ON agent_tasks(status, created);
    CREATE INDEX idx_tasks_workflow ON agent_tasks(workflow_id);
    CREATE TABLE workflows (id TEXT PRIMARY KEY, kind TEXT NOT NULL, origin TEXT, status TEXT NOT NULL, created REAL, finished REAL,
        summary TEXT);
    CREATE TABLE scheduler_jobs (name TEXT PRIMARY KEY, interval_s INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, last_run REAL,
        last_status TEXT, last_duration_ms REAL, last_error TEXT, last_result TEXT, next_run REAL, runs INTEGER NOT NULL DEFAULT 0,
        failures INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE scheduler_runs (id INTEGER PRIMARY KEY, job TEXT, started REAL, finished REAL, status TEXT, result TEXT, error TEXT);
    ALTER TABLE indicators ADD COLUMN status TEXT NOT NULL DEFAULT 'unprocessed';
    ALTER TABLE indicators ADD COLUMN verdict TEXT;
    ALTER TABLE indicators ADD COLUMN risk REAL;
    ALTER TABLE indicators ADD COLUMN registered_domain TEXT;
    ALTER TABLE indicators ADD COLUMN processed REAL;
    ALTER TABLE indicators ADD COLUMN workflow_id TEXT;
    ALTER TABLE indicators ADD COLUMN threat_id TEXT;
    CREATE INDEX idx_indicators_status ON indicators(status);
    CREATE TABLE model_evals (id INTEGER PRIMARY KEY, created REAL, kind TEXT, n INTEGER, result TEXT);
    """,
]


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=10000")
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


_local = threading.local()
_generation = 0
_migrated = -1


def db() -> sqlite3.Connection:
    """One connection per thread (the server runs handlers on a thread pool); SQLite WAL handles the concurrency."""
    global _migrated
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "gen", None) == _generation:
        return conn
    conn = _connect()
    with LOCK:
        if _migrated != _generation:
            migrate(conn)
            _migrated = _generation
    _local.conn, _local.gen = conn, _generation
    return conn


def reset_for_tests(path: Path):
    """Point the module at a fresh database file (tests only)."""
    global _generation, DB_PATH
    with LOCK:
        _generation += 1
        DB_PATH = Path(path)


def rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def one(cur):
    r = cur.fetchone()
    return dict(r) if r else None
