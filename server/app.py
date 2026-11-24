"""RAQEEB server: API for the police command centre and the resident app, plus live updates over WebSocket.

    uvicorn server.app:app --host 0.0.0.0 --port 8000
    open http://localhost:8000/          police command centre
    open http://<laptop-ip>:8000/app     resident phone app (same Wi-Fi)
"""
import asyncio
import csv
import io
import json
import socket
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from raqeeb import store
from raqeeb.brands import BRANDS, SCAM_TYPES
from raqeeb.campaigns import build as build_campaigns
from raqeeb.engine import model, scan_many
from raqeeb.hunt import candidates, crtsh, keywords_for
from raqeeb.messages import check_message
from raqeeb.scamcast import SEASONS, forecast, predicted_domains
from raqeeb.urlparse import parse

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
EVIDENCE = ROOT / "evidence"
UAE_SCAMS = ROOT / "data" / "uae_scam_urls.csv"
CAMPAIGNS: dict = {"campaigns": [], "graph": {"nodes": [], "edges": []}}
REPLAY: list[dict] = []


class Hub:
    """Fan-out of live events to every connected dashboard and phone."""

    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def join(self, ws: WebSocket):
        await ws.accept()
        self.clients.add(ws)

    def leave(self, ws: WebSocket):
        self.clients.discard(ws)

    async def send(self, event: str, data: dict):
        msg = json.dumps({"event": event, "data": data, "ts": time.time()}, ensure_ascii=False, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.leave(ws)


hub = Hub()


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


@asynccontextmanager
async def lifespan(_app):
    model()
    seed()
    yield


app = FastAPI(title="RAQEEB — UAE scam intelligence", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=WEB), name="static")


# ---------- pages ----------
@app.get("/", include_in_schema=False)
def command_page():
    return FileResponse(WEB / "command" / "index.html")


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
    return (WEB / "app" / "blocked.html").read_text(encoding="utf-8").replace("{{DOMAIN}}", d[:120])


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


def _with_block(r):
    r["blocked"] = store.is_blocked(r["host"]) if r.get("host") else False
    return r


@app.post("/api/scan")
async def api_scan(body: ScanIn):
    r = scan_many([body.url])[0]
    if body.live:
        from raqeeb.live import enrich
        r = await asyncio.to_thread(enrich, r, EVIDENCE)
        if r.get("evidence_pack"):
            r["case_id"] = Path(r["evidence_pack"]).name
    return _with_block(r)


@app.get("/api/check")
def api_check(url: str):
    return _with_block(scan_many([url])[0])


@app.post("/api/scan/batch")
def api_batch(body: BatchIn):
    if len(body.urls) > 10000:
        raise HTTPException(413, "Send at most 10,000 URLs per call")
    return scan_many(body.urls)


@app.post("/api/check-message")
async def api_message(body: MessageIn):
    r = check_message(body.text)
    for link in r["links"]:
        _with_block(link)
    if body.report:
        brand = next((l["impersonated_brand"]["name"] for l in r["links"] if l.get("impersonated_brand")), "")
        rid = store.add_report("message", body.text, r["verdict"], r["risk_score"], brand, body.emirate)
        await hub.send("report", {"id": rid, "verdict": r["verdict"], "risk": r["risk_score"], "brand": brand,
                                  "emirate": body.emirate, "preview": body.text[:140]})
        for link in r["links"]:
            if link["label"]:
                store.add_feed(link["url"], link["host"], (link.get("impersonated_brand") or {}).get("name", ""),
                               link["risk_score"], link["verdict"], "Resident report (RAQEEB app)", _top_reason(link))
                await hub.send("feed", {"url": link["url"], "risk": link["risk_score"], "verdict": link["verdict"],
                                        "brand": (link.get("impersonated_brand") or {}).get("name", ""),
                                        "source": "Resident report (RAQEEB app)", "reason": _top_reason(link)})
    return r


# ---------- intelligence ----------
@app.get("/api/feed")
def api_feed(limit: int = 200, brand: str | None = None):
    return store.feed(limit=min(limit, 1000), brand=brand)


@app.get("/api/campaigns")
def api_campaigns():
    return CAMPAIGNS


@app.get("/api/stats")
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
async def api_hunt(body: HuntIn, tasks: BackgroundTasks):
    tasks.add_task(_hunt_job, body, asyncio.get_running_loop())
    return {"started": True, "mode": body.mode}


# ---------- prevention ----------
class BlockIn(BaseModel):
    domain: str
    reason: str = ""
    brand: str = ""
    by: str = "officer"


@app.post("/api/antibody")
async def api_antibody(body: BlockIn):
    p = parse(body.domain)
    target = p.host.removeprefix("www.") or body.domain.lower()
    store.block(target, body.reason, body.brand, body.by)
    await hub.send("antibody", {"domain": target, "brand": body.brand, "reason": body.reason})
    return {"blocked": target}


@app.delete("/api/antibody/{domain}")
async def api_unblock(domain: str):
    store.unblock(domain, "officer")
    await hub.send("unblock", {"domain": domain})
    return {"unblocked": domain}


@app.get("/api/blocklist")
def api_blocklist():
    return store.blocklist()


@app.get("/api/blocklist.txt", response_class=PlainTextResponse)
def api_blocklist_txt(fmt: str = "plain"):
    doms = [b["domain"] for b in store.blocklist()]
    if fmt == "hosts":
        return "\n".join(f"0.0.0.0 {d}" for d in doms) + "\n"
    return "\n".join(doms) + "\n"


@app.get("/api/reports")
def api_reports():
    return store.reports()


# ---------- evidence ----------
class EvidenceIn(BaseModel):
    url: str


@app.post("/api/evidence")
async def api_evidence(body: EvidenceIn):
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
def api_evidence_report(case_id: str):
    return (_case(case_id) / "report.html").read_text(encoding="utf-8")


@app.get("/api/evidence/{case_id}/zip")
def api_evidence_zip(case_id: str):
    folder = _case(case_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in folder.iterdir():
            z.write(f, f.name)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="raqeeb-case-{case_id}.zip"'})


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
    return {"url": f"http://{ip}:8000/app"}


# ---------- live updates ----------
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await hub.join(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.leave(websocket)
