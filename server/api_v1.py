"""SAWNN Link Intelligence Engine API (v1): the standard, documented scan interface used by both apps."""
import json
import shutil
import threading

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from raqeeb import auth, protection
from raqeeb.db import db, rows
from raqeeb.engine import MODELS
from raqeeb.link import ml, official_domains, pipeline, source_registry
from raqeeb.link.url_validator import InvalidURL

from .deps import current_user, rate, require
from .hub import hub

router = APIRouter(prefix="/api/v1", tags=["Link Intelligence Engine"])


class ScanIn(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    mode: str = Field("quick", pattern="^(quick|deep)$")


def _deep_job(url: str, scan_id: str, user_id: int | None):
    try:
        report = pipeline.analyse(url, "deep", scan_id)
        pipeline.save(report, user_id, "complete")
    except Exception as e:  # noqa: BLE001 - keep the failure on the record instead of losing the scan
        pipeline.save({"scan_id": scan_id, "submitted_url": url, "mode": "deep", "verdict": "INCONCLUSIVE", "risk_score": None,
                       "risk_level": "UNKNOWN", "limitations": [f"Deep analysis failed: {str(e)[:200]}"]}, user_id, "failed")


@router.post("/scan", dependencies=[Depends(rate("check"))])
def scan(body: ScanIn, user=Depends(current_user)):
    """quick: offline stages, returns the full report now. deep: needs sign-in, returns 202-style {status: running};
    poll GET /api/v1/scan/{scan_id}."""
    try:
        if body.mode == "quick":
            report = pipeline.analyse(body.url, "quick")
            pipeline.save(report, user["id"] if user else None)
            return report
        if not user:
            raise HTTPException(401, "Sign in to run a deep scan")
        pipeline.url_validator.validate(body.url)
    except InvalidURL as e:
        raise HTTPException(422, str(e)) from e
    scan_id = pipeline.new_id()
    pipeline.save({"scan_id": scan_id, "submitted_url": body.url, "mode": "deep"}, user["id"], "running")
    threading.Thread(target=_deep_job, args=(body.url, scan_id, user["id"]), daemon=True).start()
    return {"scan_id": scan_id, "status": "running", "poll": f"/api/v1/scan/{scan_id}"}


@router.get("/scan/{scan_id}")
def scan_get(scan_id: str, user=Depends(current_user)):
    r = pipeline.get(scan_id)
    official = bool(user and user["role"] in auth.OFFICIAL_ROLES)
    if not r or (r["owner"] is not None and not official and not (user and user["id"] == r["owner"])):
        raise HTTPException(404, "No scan with that ID")
    r.pop("owner", None)
    return r


@router.get("/scan/{scan_id}/screenshot")
def scan_screenshot(scan_id: str, user=Depends(require("view_evidence"))):
    f = pipeline.SHOTS / f"{scan_id}.png"
    if not scan_id.replace("-", "").isalnum() or not f.exists():
        raise HTTPException(404, "No screenshot for that scan")
    return FileResponse(f, media_type="image/png", headers={"Cache-Control": "no-store"})


@router.get("/scans")
def scans_recent(user=Depends(require("view_investigations"))):
    return rows(db().execute("SELECT id, url, verdict, risk_score, mode, status, created FROM scans ORDER BY created DESC LIMIT 100"))


@router.get("/health")
def health():
    def has(mod):
        try:
            __import__(mod)
            return True
        except ImportError:
            return False
    db().execute("SELECT 1").fetchone()
    return {"status": "ok", "engine": pipeline.ENGINE_VERSION, "database": "ok", "model": ml.status()["available"],
            "optional_components": {"playwright": has("playwright"), "dnspython": has("dns.resolver"), "beautifulsoup4": has("bs4"),
                                    "tesseract_ocr": has("pytesseract") and bool(shutil.which("tesseract")),
                                    "visual_references": bool(__import__("raqeeb.link.visual", fromlist=["x"]).references())},
            "external_sources_configured": {s["name"]: s["configured"] for s in source_registry.sources() if "configured" in s},
            "protection_version": protection.latest()["payload"]["version"]}


@router.get("/models/status")
def models_status():
    out = ml.status()
    f = MODELS / "evaluation.json"
    out["comparison"] = json.loads(f.read_text()) if f.exists() else None
    return out


@router.get("/intelligence/indicators")
def indicators(user=Depends(require("view_investigations"))):
    t = rows(db().execute("""SELECT id, indicator_type, normalized, brand, category, status, severity, first_seen, last_seen, block_status, demo
        FROM threats WHERE status IN ('analyst_verified','confirmed_malicious') ORDER BY last_seen DESC LIMIT 500"""))
    return {"threats": t, "published_rules": protection.latest()["payload"]["rules"]}


@router.get("/intelligence/sources")
def sources():
    return source_registry.sources()


@router.get("/organizations")
def organisations():
    return official_domains.organisations()


class OrgIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    name_ar: str | None = None
    sector: str | None = None
    domains: list[str] = Field(min_length=1, max_length=20)
    keywords: list[str] = []
    verification_source: str | None = Field(None, max_length=300)


@router.post("/organizations")
async def organisation_add(body: OrgIn, user=Depends(require("manage_registry"))):
    o = official_domains.add_organisation(body.model_dump(), user["email"])
    db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,strftime('%s','now'),?)",
                 ("organisation_saved", json.dumps({"id": o["id"], "domains": [d["domain"] for d in o["domains"]]}), user["email"]))
    await hub.send("registry", {"id": o["id"]})
    return o


# ---------- hackathon demonstration mode (SAWNN_DEMO=1) ----------
demo_router = APIRouter(tags=["Demo mode"])


@demo_router.get("/api/public/demo")
def demo_info():
    from raqeeb import demo_scenario
    return {"enabled": demo_scenario.enabled(), "accounts": demo_scenario.public_accounts() if demo_scenario.enabled() else [],
            "note": "Demonstration-only accounts. Never reuse these passwords."}


def _demo_on():
    from raqeeb import demo_scenario
    if not demo_scenario.enabled():
        raise HTTPException(404, "Demo mode is off (start the server with SAWNN_DEMO=1)")
    return demo_scenario


@demo_router.get("/api/demo/status")
def demo_status(user=Depends(require("view_command"))):
    return _demo_on().status()


@demo_router.post("/api/demo/seed")
async def demo_seed(user=Depends(require("approve_threat"))):
    out = _demo_on().seed()
    await hub.send("threat", {"id": out["status"]["threat_id"], "status": "under_review", "status_label": "Under investigation"})
    return out


@demo_router.post("/api/demo/reset")
async def demo_reset(user=Depends(require("approve_threat"))):
    out = _demo_on().reset()
    await hub.send("protection", {"version": protection.latest()["payload"]["version"], "rules": len(protection.latest()["payload"]["rules"])}, audience="all")
    return out
