"""SAWNN agent orchestrator: a database-backed task queue, sixteen agents, hand-offs and the monitoring scheduler.

How it works
- Every piece of work is an agent task row (agent_tasks) inside a workflow (workflows). A task records agent, task ID,
  status, timings, input references, findings, evidence, confidence, sources, errors and recommended action.
- An agent returns structured results and may hand off follow-up tasks to other agents (for example URL Analysis →
  Phishing Intelligence → UAE Brand Impersonation → Campaign Correlation). Hand-offs are new queued tasks whose
  parent_id points to the task that created them, so the Command interface can draw the real chain.
- A worker thread drains the queue (start_worker). drain() runs the same loop synchronously (tests, CLI).
- The scheduler (start_scheduler) runs monitoring jobs on configurable intervals and records each run.

Safety rules enforced here
- Agents never approve threats, publish protection or issue public alerts. The discovery pipeline creates threat records
  with status "new" (Newly discovered) for analysts; distribution still needs analyst verification and official approval.
- Discovered URLs are analysed with offline stages by default. Live sandbox visits of feed URLs happen only when
  SAWNN_DISCOVERY_SANDBOX=1 (meant for an isolated sandbox host, never an ordinary workstation).
"""
import json
import os
import re
import secrets
import threading
import time
import traceback

from .db import db, one, rows

MAX_TASKS_PER_WORKFLOW = 60
MAX_DEPTH = 5
_lock = threading.Lock()
_state = {"worker": None, "scheduler": None, "notify": None, "stop": False}


def _id(prefix):
    return f"{prefix}-{time.strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"


def set_notifier(fn):
    """fn(event, data) is called (from worker threads) for analyst notifications; the server wires it to the WebSocket hub."""
    _state["notify"] = fn


def _notify(event, data):
    fn = _state["notify"]
    if fn:
        try:
            fn(event, data)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- queue
def start_workflow(kind: str, payload: dict, origin: str, first_agent: str, refs: list[str] | None = None) -> str:
    wid = _id("WF")
    now = time.time()
    db().execute("INSERT INTO workflows (id, kind, origin, status, created) VALUES (?,?,?,?,?)", (wid, kind, origin, "running", now))
    enqueue(wid, first_agent, payload, refs or [], None, 0)
    db().commit()
    return wid


def enqueue(wid, agent, payload, refs, parent, depth) -> str | None:
    n = db().execute("SELECT COUNT(*) FROM agent_tasks WHERE workflow_id=?", (wid,)).fetchone()[0]
    if n >= MAX_TASKS_PER_WORKFLOW or depth > MAX_DEPTH:
        return None
    tid = _id("TSK")
    db().execute("""INSERT INTO agent_tasks (id, workflow_id, parent_id, agent, status, input, input_refs, created, depth)
        VALUES (?,?,?,?,?,?,?,?,?)""", (tid, wid, parent, agent, "queued", json.dumps(payload, default=str)[:20000],
                                         json.dumps(refs or []), time.time(), depth))
    return tid


def _claim():
    with _lock:
        t = one(db().execute("SELECT * FROM agent_tasks WHERE status='queued' ORDER BY created LIMIT 1"))
        if not t:
            return None
        db().execute("UPDATE agent_tasks SET status='running', started=? WHERE id=? AND status='queued'", (time.time(), t["id"]))
        db().commit()
        return t


def _finish_workflow_if_done(wid):
    open_ = db().execute("SELECT COUNT(*) FROM agent_tasks WHERE workflow_id=? AND status IN ('queued','running')", (wid,)).fetchone()[0]
    if open_:
        return
    st = rows(db().execute("SELECT status, COUNT(*) n FROM agent_tasks WHERE workflow_id=? GROUP BY status", (wid,)))
    counts = {r["status"]: r["n"] for r in st}
    status = "completed" if not counts.get("failed") else ("partial" if counts.get("completed") else "failed")
    db().execute("UPDATE workflows SET status=?, finished=?, summary=? WHERE id=?", (status, time.time(), json.dumps(counts), wid))


def run_task(t: dict):
    from .sawnn_agents import AGENT_HANDLERS
    t0 = time.time()
    payload = json.loads(t["input"] or "{}")
    try:
        handler = AGENT_HANDLERS[t["agent"]]
        out = handler(payload) or {}
        status, errors = "completed", out.get("errors") or []
    except Exception as e:  # noqa: BLE001 - a failing agent is recorded, the workflow continues
        out, status, errors = {}, "failed", [f"{e.__class__.__name__}: {str(e)[:300]}", traceback.format_exc(limit=2)[-600:]]
    handoffs = []
    for h in out.get("handoffs", []):
        agent, inp, refs = h[0], h[1], (h[2] if len(h) > 2 else [])
        child = enqueue(t["workflow_id"], agent, inp, refs, t["id"], t["depth"] + 1)
        if child:
            handoffs.append({"task_id": child, "agent": agent})
    db().execute("""UPDATE agent_tasks SET status=?, finished=?, duration_ms=?, findings=?, evidence=?, confidence=?, sources=?, errors=?,
        recommended_action=?, handoffs=? WHERE id=?""",
                 (status, time.time(), round((time.time() - t0) * 1000, 1), json.dumps(out.get("findings"), default=str)[:20000],
                  json.dumps(out.get("evidence"), default=str)[:20000], out.get("confidence"), json.dumps(out.get("sources", [])),
                  json.dumps(errors) if errors else None, out.get("recommended_action"), json.dumps(handoffs), t["id"]))
    _finish_workflow_if_done(t["workflow_id"])
    db().commit()
    return status


def drain(limit: int = 500) -> int:
    n = 0
    while n < limit:
        t = _claim()
        if not t:
            break
        run_task(t)
        n += 1
    return n


def start_worker():
    if os.environ.get("SAWNN_ORCHESTRATOR", "1") == "0" or os.environ.get("SAWNN_WORKER", "1") == "0" or \
            (_state["worker"] and _state["worker"].is_alive()):
        return

    def loop():
        while not _state["stop"]:
            try:
                if not drain(50):
                    time.sleep(1.0)
            except Exception:  # noqa: BLE001
                time.sleep(2.0)
    _state["worker"] = threading.Thread(target=loop, daemon=True, name="sawnn-orchestrator")
    _state["worker"].start()


def run_sync(kind, payload, origin, first_agent, refs=None) -> dict:
    wid = start_workflow(kind, payload, origin, first_agent, refs)
    # run this workflow's tasks inline (other queued work is left for the worker)
    for _ in range(MAX_TASKS_PER_WORKFLOW + 5):
        with _lock:
            t = one(db().execute("SELECT * FROM agent_tasks WHERE workflow_id=? AND status='queued' ORDER BY created LIMIT 1", (wid,)))
            if t:
                db().execute("UPDATE agent_tasks SET status='running', started=? WHERE id=?", (time.time(), t["id"]))
                db().commit()
        if not t:
            break
        run_task(t)
    return workflow(wid)


def workflow(wid) -> dict:
    w = one(db().execute("SELECT * FROM workflows WHERE id=?", (wid,)))
    if not w:
        return {}
    w["summary"] = json.loads(w["summary"] or "{}")
    tasks = rows(db().execute("SELECT * FROM agent_tasks WHERE workflow_id=? ORDER BY created", (wid,)))
    for t in tasks:
        for k in ("input", "input_refs", "findings", "evidence", "sources", "errors", "handoffs"):
            t[k] = json.loads(t[k]) if t.get(k) else None
    w["tasks"] = tasks
    return w


def activity(limit=80) -> dict:
    tasks = rows(db().execute("""SELECT id, workflow_id, parent_id, agent, status, created, started, finished, duration_ms, confidence,
        recommended_action, errors, handoffs, input_refs FROM agent_tasks ORDER BY created DESC LIMIT ?""", (limit,)))
    for t in tasks:
        for k in ("errors", "handoffs", "input_refs"):
            t[k] = json.loads(t[k]) if t.get(k) else None
    stats = rows(db().execute("""SELECT agent, COUNT(*) total, SUM(status='completed') completed, SUM(status='failed') failed,
        SUM(status IN ('queued','running')) open, AVG(duration_ms) avg_ms, MAX(finished) last FROM agent_tasks GROUP BY agent"""))
    wf = rows(db().execute("SELECT * FROM workflows ORDER BY created DESC LIMIT 30"))
    for w in wf:
        w["summary"] = json.loads(w["summary"] or "{}")
    q = one(db().execute("SELECT SUM(status='queued') queued, SUM(status='running') running FROM agent_tasks"))
    return {"tasks": tasks, "agents": stats, "workflows": wf, "queue": {"queued": q["queued"] or 0, "running": q["running"] or 0},
            "worker_running": bool(_state["worker"] and _state["worker"].is_alive())}


# ---------------------------------------------------------------- entry points used by the apps
def on_citizen_report(report: dict, text: str):
    """A citizen report enters the shared pipeline: message + social-engineering analysis, then each link/number."""
    if os.environ.get("SAWNN_ORCHESTRATOR", "1") == "0":
        return None
    return start_workflow("citizen_report", {"text": (text or "")[:4000], "report_ref": report.get("ref")}, f"citizen report {report.get('ref')}",
                          "message_intelligence", [f"report:{report.get('ref')}"])


def process_discoveries(batch: int = 50) -> dict:
    """Global Threat Hunter: queue analysis for indicators collected by the discovery engine but not yet processed."""
    pending = rows(db().execute("SELECT value, source FROM indicators WHERE status='unprocessed' ORDER BY first_seen LIMIT ?", (batch,)))
    if not pending:
        return {"queued": 0}
    wid = start_workflow("discovery_batch", {"count": len(pending)}, "SAWNN Global Threat Discovery Engine", "global_threat_hunter",
                         [f"indicator:{p['value']}" for p in pending[:20]])
    db().executemany("UPDATE indicators SET status='queued', workflow_id=? WHERE value=?", [(wid, p["value"]) for p in pending])
    db().execute("UPDATE agent_tasks SET input=? WHERE workflow_id=? AND agent='global_threat_hunter'",
                 (json.dumps({"indicators": pending}), wid))
    db().commit()
    return {"queued": len(pending), "workflow_id": wid}


# ---------------------------------------------------------------- scheduler
def _m(name, default):
    return int(os.environ.get(name) or default)


def job_specs() -> dict:
    """Monitoring jobs and their intervals (seconds). Override with SAWNN_SCHED_<JOB>_MIN."""
    spec = {
        "feeds_high_priority": (15, "OpenPhish, URLhaus recent, Phishing.Database last hour"),
        "feeds_other": (60, "Phishing.Database today, PhishTank"),
        "process_discoveries": (10, "Global Threat Hunter: analyse newly collected indicators"),
        "uae_brand_discovery": (120, "UAE brand impersonation sweep over new indicators and look-alike candidates"),
        "suspicious_domain_discovery": (120, "Look-alike domains for UAE brands that resolve in DNS"),
        "campaign_correlation": (30, "Group related indicators into campaigns"),
        "seasonal_analysis": (1440, "Seasonal threat outlook"),
        "intelligence_briefing": (1440, "Daily intelligence briefing"),
        "source_health": (10, "Reachability of every monitored source"),
        "model_evaluation": (1440, "Re-evaluate the engine on the labelled UAE set and analyst decisions"),
    }
    return {k: {"interval_s": 60 * _m(f"SAWNN_SCHED_{k.upper()}_MIN", m), "description": d} for k, (m, d) in spec.items()}


def _job(name) -> dict:
    from . import discovery
    if name == "feeds_high_priority":
        res = [discovery.collect(s) for s in ("openphish", "urlhaus_recent", "phishing_database_hour")]
        return {"runs": [{k: r[k] for k in ("source", "status", "new_indicators", "duplicates", "error")} for r in res]}
    if name == "feeds_other":
        res = [discovery.collect(s) for s in ("phishing_database_today", "phishtank")]
        return {"runs": [{k: r[k] for k in ("source", "status", "new_indicators", "duplicates", "error")} for r in res]}
    if name == "process_discoveries":
        return process_discoveries(_m("SAWNN_DISCOVERY_BATCH", 50))
    if name == "uae_brand_discovery":
        return {"workflow_id": start_workflow("uae_brand_sweep", {}, "scheduler", "uae_brand_impersonation")}
    if name == "suspicious_domain_discovery":
        return {"workflow_id": start_workflow("lookalike_sweep", {"mode": "lookalikes"}, "scheduler", "global_threat_hunter")}
    if name == "campaign_correlation":
        return {"workflow_id": start_workflow("correlation", {}, "scheduler", "campaign_correlation")}
    if name == "seasonal_analysis":
        return {"workflow_id": start_workflow("seasonal", {}, "scheduler", "seasonal")}
    if name == "intelligence_briefing":
        return {"workflow_id": start_workflow("briefing", {"period": "day"}, "scheduler", "briefing")}
    if name == "source_health":
        return discovery.health_check()
    if name == "model_evaluation":
        return evaluate_now()
    raise KeyError(name)


def run_job(name) -> dict:
    t0 = time.time()
    try:
        result, status, err = _job(name), "ok", None
        if isinstance(result, dict) and result.get("runs") and all(r["status"] != "ok" for r in result["runs"]):
            status, err = "failed", "; ".join(f"{r['source']}: {r['error']}" for r in result["runs"] if r.get("error"))[:400]
        elif isinstance(result, dict) and result.get("runs") and any(r["status"] != "ok" for r in result["runs"]):
            status = "partial"
    except Exception as e:  # noqa: BLE001
        result, status, err = None, "failed", f"{e.__class__.__name__}: {str(e)[:300]}"
    spec = job_specs()[name]
    now = time.time()
    db().execute("""INSERT INTO scheduler_jobs (name, interval_s, last_run, last_status, last_duration_ms, last_error, last_result, next_run, runs, failures)
        VALUES (?,?,?,?,?,?,?,?,1,?) ON CONFLICT(name) DO UPDATE SET interval_s=excluded.interval_s, last_run=excluded.last_run,
        last_status=excluded.last_status, last_duration_ms=excluded.last_duration_ms, last_error=excluded.last_error,
        last_result=excluded.last_result, next_run=excluded.next_run, runs=runs+1, failures=failures+excluded.failures""",
                 (name, spec["interval_s"], now, status, round((now - t0) * 1000, 1), err, json.dumps(result, default=str)[:4000],
                  now + spec["interval_s"], int(status == "failed")))
    db().execute("INSERT INTO scheduler_runs (job, started, finished, status, result, error) VALUES (?,?,?,?,?,?)",
                 (name, t0, now, status, json.dumps(result, default=str)[:4000], err))
    db().commit()
    return {"job": name, "status": status, "result": result, "error": err}


def scheduler_status() -> dict:
    specs = job_specs()
    have = {r["name"]: r for r in rows(db().execute("SELECT * FROM scheduler_jobs"))}
    jobs = []
    for name, sp in specs.items():
        r = have.get(name, {})
        jobs.append({"name": name, "description": sp["description"], "interval_min": sp["interval_s"] // 60, "last_run": r.get("last_run"),
                     "last_status": r.get("last_status") or "never run", "last_duration_ms": r.get("last_duration_ms"),
                     "last_error": r.get("last_error"), "next_run": r.get("next_run"), "runs": r.get("runs", 0), "failures": r.get("failures", 0)})
    running = bool(_state["scheduler"] and _state["scheduler"].is_alive())
    return {"enabled": os.environ.get("SAWNN_SCHEDULER_ENABLED", "1") != "0", "running": running, "jobs": jobs,
            "recent_runs": rows(db().execute("SELECT * FROM scheduler_runs ORDER BY id DESC LIMIT 40"))}


def start_scheduler():
    if os.environ.get("SAWNN_SCHEDULER_ENABLED", "1") == "0" or (_state["scheduler"] and _state["scheduler"].is_alive()):
        return

    def loop():
        time.sleep(5)  # let the server finish starting
        while not _state["stop"]:
            now = time.time()
            due = {r["name"]: r["next_run"] for r in rows(db().execute("SELECT name, next_run FROM scheduler_jobs"))}
            for name in job_specs():
                if (due.get(name) or 0) <= now:
                    run_job(name)
            time.sleep(20)
    _state["scheduler"] = threading.Thread(target=loop, daemon=True, name="sawnn-scheduler")
    _state["scheduler"].start()


# ---------------------------------------------------------------- continuous evaluation
def evaluate_now() -> dict:
    """Evaluate the live engine on the hand-labelled UAE set plus every analyst decision recorded in SAWNN
    (approved or verified threats = phishing; false positives = legitimate). Stored in model_evals."""
    import pandas as pd

    from .link import pipeline
    from pathlib import Path
    labelled = []
    f = Path(__file__).resolve().parent.parent / "data" / "uae_eval.csv"
    if f.exists():
        d = pd.read_csv(f)
        labelled += list(zip(d.url, d.label.astype(int), ["uae_eval"] * len(d)))
    for r in rows(db().execute("SELECT original, status FROM threats WHERE indicator_type IN ('url','domain') AND demo=0 AND status IN ('confirmed_malicious','analyst_verified','false_positive')")):
        labelled.append((r["original"], 0 if r["status"] == "false_positive" else 1, "analyst_decision"))
    tp = fp = fn = tn = 0
    errors = []
    for url, y, src in labelled:
        try:
            v = pipeline.analyse(url, "quick")["verdict"]
        except Exception as e:  # noqa: BLE001
            errors.append(str(e)[:80])
            continue
        flagged = v == "MALICIOUS"
        tp += flagged and y == 1
        fp += flagged and y == 0
        fn += (not flagged) and y == 1
        tn += (not flagged) and y == 0
    res = {"n": tp + fp + fn + tn, "malicious_precision": round(tp / (tp + fp), 4) if tp + fp else None,
           "malicious_recall": round(tp / (tp + fn), 4) if tp + fn else None, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
           "sources": sorted({s for *_, s in labelled}), "errors": errors[:5],
           "note": "Small set: a monitoring signal for regressions, not proof of the precision target."}
    db().execute("INSERT INTO model_evals (created, kind, n, result) VALUES (?,?,?,?)", (time.time(), "continuous", res["n"], json.dumps(res)))
    db().commit()
    return res


_ = re
