"""MIRA API v1 additions: attachments, reports, sandbox, model metrics, threat discovery, citizen alerts, agents.

Every route reuses the same service functions the apps use (no parallel logic), and every route that touches
investigations, evidence or publishing is behind a role permission. OpenAPI docs: /docs (Swagger) and /redoc.
"""
import asyncio
import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from raqeeb import agents as core_agents
from raqeeb import alerts, attachments, auth, community, discovery, mira_agents
from raqeeb.db import db, rows
from raqeeb.engine import MODELS
from raqeeb.link import pipeline, sandbox_config, source_registry

from .deps import current_user, rate, require, require_user
from .hub import hub
from .v2 import citizen_report, citizen_report_view

router = APIRouter(prefix="/api/v1", tags=["MIRA"])


# ---------- attachments ----------
@router.post("/attachments/analyze", dependencies=[Depends(rate("upload"))])
async def attachment_analyze(file: UploadFile = File(...), user=Depends(current_user)):
    """Image, screenshot, QR image, PDF or text file. The file is analysed in memory and never executed."""
    data = await file.read(attachments.MAX_BYTES + 1)
    try:
        rep = await asyncio.to_thread(attachments.analyse, data, file.filename or "", file.content_type or "")
    except attachments.AttachmentError as e:
        raise HTTPException(422, str(e)) from e
    db().execute("INSERT INTO attachments (id, sha256, kind, size, report, user_id, created) VALUES (?,?,?,?,?,?,strftime('%s','now'))",
                 (rep["attachment_id"], rep["sha256"], rep["detected_type"], rep["size_bytes"], json.dumps(rep, default=str)[:200000],
                  user["id"] if user else None))
    db().commit()
    return rep


# ---------- reports (standard names for the existing citizen-report service) ----------
router.add_api_route("/reports", citizen_report, methods=["POST"], dependencies=[Depends(rate("report"))],
                     summary="Submit a citizen report (multipart: type, text, emirate, impact, file)")


@router.get("/reports")
def reports_list(status: str | None = None, user=Depends(require_user)):
    """Officials: the review queue. Citizens: their own reports with status."""
    if user["role"] in auth.OFFICIAL_ROLES:
        if not auth.can(user["role"], "view_investigations"):
            raise HTTPException(403, "Your role doesn’t allow this action")
        out = community.queue(status)
        for r in out:
            r.pop("ip_hash", None)
        return out
    return community.my_reports(user["id"])


@router.get("/reports/{ref}")
def report_get(ref: str, user=Depends(require_user)):
    if user["role"] in auth.OFFICIAL_ROLES and auth.can(user["role"], "view_investigations"):
        r = community.get_report(ref)
        if not r:
            raise HTTPException(404, "No report with that reference")
        r.pop("ip_hash", None)
        return r
    return citizen_report_view(ref, user)


# ---------- sandbox ----------
@router.get("/sandbox/configuration")
def sandbox_configuration(user=Depends(require("view_investigations"))):
    return sandbox_config.config()


@router.get("/sandbox/{scan_id}")
def sandbox_result(scan_id: str, user=Depends(require("view_evidence"))):
    r = pipeline.get(scan_id)
    if not r:
        raise HTTPException(404, "No scan with that ID")
    return {"scan_id": scan_id, "status": r.get("status"), "mode": r.get("mode"), "analysis_status": r.get("analysis_status"),
            "submitted_url": r.get("submitted_url"), "final_url": r.get("final_url"), "verdict": r.get("verdict"),
            "website_analysis": r.get("website_analysis"), "redirects": r.get("redirects"), "visual_analysis": r.get("visual_analysis"),
            "domain_intelligence": r.get("domain_intelligence"), "parameters_collected": sandbox_config.collected(r),
            "limitations": r.get("limitations", [])}


# ---------- models ----------
@router.get("/models/metrics")
def models_metrics():
    out = {}
    for name in ("evaluation_mira.json", "evaluation_verdicts.json"):
        f = MODELS / name
        out[name.removesuffix(".json")] = json.loads(f.read_text()) if f.exists() else None
    meta = json.loads((MODELS / "meta.json").read_text())
    out["deployed"] = {k: meta.get(k) for k in ("model_version", "dataset_version", "trained_at", "threshold", "threshold_strict", "rows", "mode")}
    return out


# ---------- intelligence ----------
@router.get("/intelligence/campaigns")
def intelligence_campaigns(user=Depends(require("view_investigations"))):
    g = core_agents.correlate()
    return {"campaigns": g.get("campaigns", []) if isinstance(g, dict) else [], "graph": g}


@router.get("/intelligence/sources/status")
def intelligence_sources_status(user=Depends(require("view_investigations"))):
    return {"discovery": discovery.status(), "registry": source_registry.sources()}


@router.post("/intelligence/discovery/run")
async def discovery_run(user=Depends(require("run_hunt"))):
    res = await asyncio.to_thread(discovery.run_all)
    db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,strftime('%s','now'),?)",
                 ("discovery_run", json.dumps([{k: r[k] for k in ("source", "status", "new_indicators")} for r in res]), user["email"]))
    db().commit()
    return {"runs": res}


# ---------- citizen alerts (notifications) ----------
class AlertIn(BaseModel):
    category: str = "other"
    severity: str = "medium"
    audience: dict = Field(default_factory=lambda: {"kind": "all"})
    channels: list[str] = Field(default_factory=lambda: ["in_app"])
    content: dict = Field(default_factory=dict)
    brands: list[str] = []
    threat_ids: list[str] = []
    expires_in_days: int | None = 14
    ai_drafted: bool = False


class DraftIn(BaseModel):
    category: str
    brands: list[str] = []
    signals: list[str] = []


class ReviewIn(BaseModel):
    approve: bool
    note: str = ""


def _err(fn, *a):
    try:
        return fn(*a)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from e
    except alerts.AlertError as e:
        raise HTTPException(409, str(e)) from e


@router.get("/notifications")
def notifications(status: str | None = None, user=Depends(current_user)):
    """Command users with view_command get the alert workflow; everyone else gets the alerts published for them."""
    if user and auth.can(user["role"], "view_command"):
        return {"alerts": alerts.list_all(status), "categories": alerts.CATEGORIES, "channels": {
            c: (True if env is None else bool(__import__("os").environ.get(env))) for c, env in alerts.CHANNELS.items()}}
    return {"alerts": alerts.for_citizen(user)}


@router.post("/notifications")
def notification_create(body: AlertIn, user=Depends(require("edit_investigation"))):
    return _err(alerts.create, body.model_dump(), user, body.ai_drafted)


@router.post("/notifications/draft")
def notification_draft(body: DraftIn, user=Depends(require("edit_investigation"))):
    return _err(alerts.ai_draft, body.category, body.brands, body.signals)


@router.put("/notifications/{aid}")
def notification_update(aid: str, body: AlertIn, user=Depends(require("edit_investigation"))):
    return _err(alerts.update, aid, body.model_dump(), user)


@router.post("/notifications/{aid}/submit")
def notification_submit(aid: str, user=Depends(require("edit_investigation"))):
    return _err(alerts.submit, aid, user)


@router.post("/notifications/{aid}/review")
def notification_review(aid: str, body: ReviewIn, user=Depends(require("verify_threat"))):
    return _err(alerts.review, aid, user, body.approve, body.note)


@router.post("/notifications/{aid}/approve")
def notification_approve(aid: str, user=Depends(require("approve_threat"))):
    return _err(alerts.approve, aid, user)


@router.post("/notifications/{aid}/publish")
async def notification_publish(aid: str, user=Depends(require("approve_threat"))):
    a = _err(alerts.publish, aid, user)
    await hub.send("citizen_alert", {"id": aid, "title": a["content"]["en"]["title"], "title_ar": a["content"]["ar"]["title"],
                                     "severity": a["severity"]}, audience="all")
    return a


@router.post("/notifications/{aid}/withdraw")
def notification_withdraw(aid: str, user=Depends(require("approve_threat"))):
    return _err(alerts.withdraw, aid, user)


class EngageIn(BaseModel):
    action: str = Field(pattern="^(opened|acknowledged|reported_related)$")


@router.post("/notifications/{aid}/engage")
def notification_engage(aid: str, body: EngageIn, user=Depends(require_user)):
    return _err(alerts.engage, aid, user, body.action)


class SubsIn(BaseModel):
    categories: list[str]


@router.post("/notifications/subscriptions")
def notification_subscriptions(body: SubsIn, user=Depends(require_user)):
    cats = [c for c in body.categories if c in alerts.CATEGORIES]
    db().execute("DELETE FROM alert_subscriptions WHERE user_id = ?", (user["id"],))
    db().executemany("INSERT INTO alert_subscriptions VALUES (?,?)", [(user["id"], c) for c in cats])
    db().commit()
    return {"categories": cats}


# ---------- agents ----------
@router.get("/agents")
def agent_catalogue(user=Depends(require("view_command"))):
    recent = rows(db().execute("SELECT agent, COUNT(*) n, MAX(created) last FROM findings GROUP BY agent"))
    stats = {r["agent"]: r for r in recent}
    return [a | {"runs": stats.get(a["id"], {}).get("n", 0), "last_run": stats.get(a["id"], {}).get("last")} for a in mira_agents.catalogue()]


class AgentIn(BaseModel):
    input: str | None = Field(None, max_length=4000)


@router.post("/agents/{agent_id}/run")
async def agent_run(agent_id: str, body: AgentIn, request: Request, user=Depends(require("view_investigations"))):
    try:
        return await asyncio.to_thread(mira_agents.run, agent_id, body.input)
    except KeyError as e:
        raise HTTPException(404, "Unknown agent") from e


_ = (Form,)
