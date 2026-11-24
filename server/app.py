"""SAWNN server: SAWNN Command (officials), SAWNN Protect (citizens) and the intelligence API, with live updates.

    uvicorn server.app:app --host 0.0.0.0 --port 8000
    open http://localhost:8000/          SAWNN Command (sign in with an account from data/first_run_credentials.txt)
    open http://<laptop-ip>:8000/app     SAWNN Protect, the citizen app (same Wi-Fi)
"""
import asyncio
import csv
import html
import io
import json
import os
import socket
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from raqeeb import auth, content, intel, protection, store
from raqeeb.brands import BRANDS, SCAM_TYPES
from raqeeb.campaigns import build as build_campaigns
from raqeeb.engine import model, scan_many
from raqeeb.hunt import candidates, crtsh, keywords_for
from raqeeb.messages import check_message
from raqeeb.scamcast import SEASONS, forecast, predicted_domains
from raqeeb.urlparse import parse

from .deps import current_user, rate, require, require_official
from .hub import hub
from .api_v1 import demo_router
from .api_v1 import router as v1_router
from .v2 import router as v2_router

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
EVIDENCE = ROOT / "evidence"
UAE_SCAMS = ROOT / "data" / "uae_scam_urls.csv"
CAMPAIGNS: dict = {"campaigns": [], "graph": {"nodes": [], "edges": []}}
REPLAY: list[dict] = []


def _top_reason(r):
    return r["reasons"][0]["en"] if r["reasons"] else ""


def seed():
    """Load the real UAE-targeted scam URLs mined from public feeds into the feed and build campaigns."""
    global CAMPAIGNS, REPLAY
    if not UAE_SCAMS.exists():
        return
    rows = list(csv.DictReader(UAE_SCAMS.open(encoding="utf-8")))
    CAMPAIGNS = build_campaigns(rows)
    REPLAY = rows
    if store.feed(limit=1):
        return
    results = scan_many([r["url"] for r in rows])
    for row, res in zip(rows, results):  # ts=0: imported history, shown without a time
        store.add_feed(row["url"], res["host"], row["brand"], res["risk_score"], res["verdict"],
                       f"Reported in {row['source']}", _top_reason(res), ts=0)


async def _expiry_loop():
    """Every hour: expire global blocks past their date and send them back to review."""
    while True:
        pkg = await asyncio.to_thread(protection.expire_due)
        if pkg:
            await hub.send("protection", {"version": pkg["payload"]["version"], "rules": len(pkg["payload"]["rules"])}, audience="all")
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(_app):
    model()
    created = auth.bootstrap()
    if created:
        print("SAWNN Command accounts created. Credentials: data/first_run_credentials.txt")
    from raqeeb import demo_scenario
    if demo_scenario.enabled():
        demo_scenario.ensure_accounts()
        print("DEMO MODE: demo accounts are active (admin@sawnn.demo, analyst@sawnn.demo, citizen@sawnn.demo)")
    seed()
    protection.latest()
    from raqeeb import discovery
    discovery.start_scheduler()
    task = asyncio.create_task(_expiry_loop())
    yield
    task.cancel()


app = FastAPI(title="SAWNN API", version="3.0", lifespan=lifespan,
              description="SAWNN (صون) shared threat-intelligence backend for SAWNN Protect and SAWNN Command. "
                          "See docs/API_GUIDE.md for configuration of every external service.")
_origins = [o for o in os.environ.get("SAWNN_CORS_ORIGINS", "").split(",") if o]
if _origins:
    app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=WEB), name="static")
app.include_router(v2_router)
app.include_router(v1_router)
app.include_router(demo_router)
from .api_sawnn import router as sawnn_router  # noqa: E402
from .signin_demo import router as signin_router  # noqa: E402
app.include_router(sawnn_router)
app.include_router(signin_router)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "font-src 'self'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers.setdefault("Content-Security-Policy", CSP)
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# ---------- pages ----------
@app.get("/", include_in_schema=False)
def entry_page():
    return FileResponse(WEB / "index.html")


@app.get("/command", include_in_schema=False)
def command_page():
    return FileResponse(WEB / "command" / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(WEB / "app" / "icon-192.png", media_type="image/png")


@app.get("/signin", include_in_schema=False)
def signin_page():
    return FileResponse(WEB / "signin" / "index.html")


@app.get("/app", include_in_schema=False)
def resident_app():
    return FileResponse(WEB / "app" / "index.html")


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifest():
    return FileResponse(WEB / "app" / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
def service_worker():
    return FileResponse(WEB / "app" / "sw.js", media_type="application/javascript")


@app.get("/blocked", response_class=HTMLResponse, include_in_schema=False)
def blocked_page(d: str = ""):
    return (WEB / "app" / "blocked.html").read_text(encoding="utf-8").replace("{{DOMAIN}}", html.escape(d[:120]))


# ---------- scanning ----------
class ScanIn(BaseModel):
    url: str
    live: bool = False
    source: str = "manual"


class BatchIn(BaseModel):
    urls: list[str]


class MessageIn(BaseModel):
    text: str
    report: bool = False
    emirate: str = "Abu Dhabi"


def _demo_note(text):
    from raqeeb import demo_scenario
    if demo_scenario.enabled():
        demo_scenario.note_citizen_check(text)


def _with_block(r):
    r["blocked"] = bool(r.get("host") and (protection.check_value(r["url"]) or store.is_blocked(r["host"])))
    return r


@app.post("/api/scan", dependencies=[Depends(rate("check"))])
async def api_scan(body: ScanIn, user=Depends(current_user)):
    if body.live and not (user and auth.can(user["role"], "view_evidence")):
        raise HTTPException(403, "Live evidence collection is for authorised officials")
    content.bump("checks")
    r = scan_many([body.url])[0]
    if body.live:
        from raqeeb.live import enrich
        r = await asyncio.to_thread(enrich, r, EVIDENCE)
        if r.get("evidence_pack"):
            r["case_id"] = Path(r["evidence_pack"]).name
    return _with_block(r)


@app.get("/api/check", dependencies=[Depends(rate("check"))])
def api_check(url: str):
    content.bump("checks")
    _demo_note(url)
    r = _with_block(scan_many([url])[0])
    if r["blocked"]:
        content.bump("checks_blocked")
    return r


@app.post("/api/scan/batch")
def api_batch(body: BatchIn, user=Depends(current_user)):
    cap = 10000 if user and user["role"] in auth.OFFICIAL_ROLES else 50
    if len(body.urls) > cap:
        raise HTTPException(413, f"Send at most {cap:,} URLs per call")
    return scan_many(body.urls)


@app.post("/api/check-message", dependencies=[Depends(rate("check"))])
async def api_message(body: MessageIn, user=Depends(current_user)):
    """Check a message. With report=true it is filed through the SAWNN 2.0 citizen-report pipeline."""
    from raqeeb import community
    content.bump("checks")
    _demo_note(body.text)
    r = check_message(body.text)
    for link in r["links"]:
        _with_block(link)
    if body.report:
        emirate = body.emirate if body.emirate in auth.EMIRATES else None
        rep = await asyncio.to_thread(community.submit, user, "auto", body.text, emirate)
        r["report_ref"] = rep["ref"]
        await hub.send("citizen_report", {"ref": rep["ref"], "type": rep["type"], "risk": rep["risk"],
                                          "severity": rep["severity"], "emirate": emirate, "threats": rep["threat_refs"]})
    return r


# ---------- intelligence ----------
@app.get("/api/feed", dependencies=[Depends(require("view_investigations"))])
def api_feed(limit: int = 200, brand: str | None = None):
    return store.feed(limit=min(limit, 1000), brand=brand)


@app.get("/api/campaigns", dependencies=[Depends(require("view_investigations"))])
def api_campaigns():
    return CAMPAIGNS


@app.get("/api/stats", dependencies=[Depends(require_official)])
def api_stats():
    s = store.stats()
    s["campaigns"] = len(CAMPAIGNS["campaigns"])
    s["model"] = model().meta.get("test_metrics", {})
    return s


@app.get("/api/brands")
def api_brands():
    return {"brands": BRANDS, "scam_types": SCAM_TYPES}


@app.get("/api/scamcast")
def api_scamcast():
    return {"active": forecast(), "all_seasons": [{k: v for k, v in s.items() if k != "months"} for s in SEASONS]}


# ---------- hunting ----------
class HuntIn(BaseModel):
    mode: str = "scamcast"          # scamcast | permute | crtsh | replay
    brand: str | None = None
    season: str | None = None
    limit: int = 400


def _resolve(d):
    try:
        return socket.gethostbyname(d)
    except OSError:
        return None


def _hunt_job(body: HuntIn, loop):
    def emit(event, data):
        asyncio.run_coroutine_threadsafe(hub.send(event, data), loop)

    emit("hunt", {"status": "started", "mode": body.mode})
    if body.mode == "replay":
        rows = [r for r in REPLAY if not body.brand or r["brand_id"] == body.brand][: body.limit]
        doms, source = [r["url"] for r in rows], "Replay of reported scam (public feed)"
        found = [(u, "") for u in doms]
    else:
        if body.mode == "crtsh":
            doms, source = crtsh(7, keywords_for([body.brand] if body.brand else None)), "New TLS certificate (crt.sh)"
        elif body.mode == "permute":
            doms = []
            for b in BRANDS:
                if not body.brand or b["id"] == body.brand:
                    doms += candidates(b, 400)
            source = "Look-alike permutation (registered)"
        else:
            seasons = [s for s in SEASONS if not body.season or s["id"] == body.season]
            doms = sorted({d for s in seasons for d in predicted_domains(s)})
            source = "ScamCast watchlist (registered)"
        doms = doms[: body.limit]
        with ThreadPoolExecutor(48) as ex:
            ips = list(ex.map(_resolve, doms))
        found = [(d, ip) for d, ip in zip(doms, ips) if ip] if body.mode != "crtsh" else [(d, "") for d in doms]
    results = scan_many([d for d, _ in found]) if found else []
    hits = 0
    for (d, ip), r in zip(found, results):
        brand = (r.get("impersonated_brand") or {}).get("name", "")
        store.add_feed(d, r["host"], brand, r["risk_score"], r["verdict"], source + (f" · {ip}" if ip else ""), _top_reason(r))
        if r["risk_score"] >= 35:
            hits += 1
            emit("feed", {"url": d, "risk": r["risk_score"], "verdict": r["verdict"], "brand": brand,
                          "source": source, "reason": _top_reason(r)})
            if body.mode == "replay":
                time.sleep(0.6)
    emit("hunt", {"status": "done", "mode": body.mode, "checked": len(doms), "found": len(found), "flagged": hits})


@app.post("/api/hunt")
async def api_hunt(body: HuntIn, tasks: BackgroundTasks, user=Depends(require("run_hunt"))):
    tasks.add_task(_hunt_job, body, asyncio.get_running_loop())
    return {"started": True, "mode": body.mode}


# ---------- prevention ----------
class BlockIn(BaseModel):
    domain: str
    reason: str = ""
    brand: str = ""


@app.post("/api/antibody")
async def api_antibody(body: BlockIn, user=Depends(require("approve_block"))):
    """One-step officer block (1.0 'antibody'), now routed through the 2.0 policy: the domain becomes a threat record,
    is confirmed by this approver, and is published in a new signed protection version with an expiry."""
    from raqeeb import community
    p = parse(body.domain)
    target = p.host.removeprefix("www.") or body.domain.lower()
    r = scan_many([target])[0]
    t, _ = intel.upsert("domain", target, intel.category_for("domain", None, None), body.brand or
                        (r.get("impersonated_brand") or {}).get("name", ""), r["risk_score"], r["risk_score"] / 100,
                        {"officer_reason": body.reason[:300]}, None, source=f"officer:{user['email']}", actor=user["email"])
    if t["status"] != "confirmed_malicious":
        community.review(t["id"], "confirmed_malicious", user, body.reason or "confirmed by approver")
    pkg = protection.global_block(t["id"], user, note=body.reason)
    store.block(target, body.reason, body.brand, user["email"])
    await hub.send("antibody", {"domain": target, "brand": body.brand, "reason": body.reason}, audience="all")
    await hub.send("protection", {"version": pkg["payload"]["version"], "rules": len(pkg["payload"]["rules"])}, audience="all")
    return {"blocked": target, "threat_id": t["id"], "version": pkg["payload"]["version"]}


@app.delete("/api/antibody/{domain}")
async def api_unblock(domain: str, user=Depends(require("approve_block"))):
    store.unblock(domain, user["email"])
    t = intel.find("domain", domain)
    if t and t["block_status"] == "global":
        protection.unblock(t["id"], user, "lifted by approver")
    else:
        protection.publish(user["email"], f"Unblock {domain}")
    await hub.send("unblock", {"domain": domain}, audience="all")
    return {"unblocked": domain}


@app.get("/api/blocklist")
def api_blocklist():
    """Domains currently blocked for everyone (from the latest signed protection package)."""
    return [{"domain": r["value"], "brand": r["brand"], "reason": r["category"], "expires": r["expires"]}
            for r in protection.latest()["payload"]["rules"] if r["type"] in ("domain", "host")]


@app.get("/api/blocklist.txt", response_class=PlainTextResponse)
def api_blocklist_txt(fmt: str = "plain"):
    doms = protection.domain_rules_for_dns()
    if fmt == "hosts":
        return "\n".join(f"0.0.0.0 {d}" for d in doms) + "\n"
    return "\n".join(doms) + "\n"


@app.get("/api/reports", dependencies=[Depends(require("view_investigations"))])
def api_reports():
    return store.reports()


# ---------- evidence ----------
class EvidenceIn(BaseModel):
    url: str


@app.post("/api/evidence")
async def api_evidence(body: EvidenceIn, user=Depends(require("view_evidence"))):
    from raqeeb.evidence import write_pack
    from raqeeb.live import enrich
    r = scan_many([body.url])[0]
    try:
        r = await asyncio.to_thread(enrich, r, EVIDENCE)
    except Exception as e:  # noqa: BLE001 - offline venue: still produce a pack from the offline verdict
        r["live"] = {"error": str(e)[:200]}
    folder = Path(r["evidence_pack"]) if r.get("evidence_pack") else write_pack(r, "", None, EVIDENCE)
    return {"case_id": folder.name, "result": r}


def _case(case_id: str) -> Path:
    f = (EVIDENCE / case_id).resolve()
    if EVIDENCE.resolve() not in f.parents or not f.is_dir():
        raise HTTPException(404, "No evidence pack with that id")
    return f


@app.get("/api/evidence/{case_id}/report", response_class=HTMLResponse)
def api_evidence_report(case_id: str, user=Depends(require("view_evidence"))):
    return (_case(case_id) / "report.html").read_text(encoding="utf-8")


@app.get("/api/evidence/{case_id}/zip")
def api_evidence_zip(case_id: str, user=Depends(require("view_evidence"))):
    folder = _case(case_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in folder.iterdir():
            z.write(f, f.name)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="sawnn-case-{case_id}.zip"'})


@app.get("/api/qr", include_in_schema=False)
def api_qr(data: str):
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(data[:300], image_factory=qrcode.image.svg.SvgPathImage, box_size=12, border=2)
    return Response(img.to_string(), media_type="image/svg+xml")


@app.get("/api/join-url")
def api_join_url():
    """The URL phones on the same Wi-Fi should open (the laptop's LAN address)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return {"url": f"http://{ip}:{os.environ.get('SAWNN_PORT', '8000')}/app"}


# ---------- live updates ----------
@app.websocket("/ws")
async def ws(websocket: WebSocket, token: str | None = None):
    await hub.join(websocket, token)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.leave(websocket)
