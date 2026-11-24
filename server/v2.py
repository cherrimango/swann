"""RAQEEB 2.0 API: accounts, threat intelligence, citizen reporting, rewards and protection distribution."""
import asyncio
import json
import re
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from raqeeb import agents, auth, community, content, intel, protection, rewards
from raqeeb.db import db, rows
from raqeeb.engine import scan_many
from raqeeb.messages import check_message
from raqeeb.security import LIMITS, BadUpload, UnsafeTarget, ip_hash, limiter, ocr_image, read_image, safe_get, store_image

from .deps import client_ip, current_user, rate, require, require_official, require_user
from .hub import hub

router = APIRouter()
ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"


def audit(action: str, actor: dict | None, detail: dict):
    db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,?,?)",
                 (action, json.dumps(detail, default=str)[:4000], time.time(), (actor or {}).get("email", "anonymous")))


# ============ accounts ============
class RegisterIn(BaseModel):
    email: str
    password: str
    display_name: str | None = None
    emirate: str | None = None
    public_rank: bool = True


class LoginIn(BaseModel):
    email: str
    password: str


@router.post("/api/auth/register", dependencies=[Depends(rate("register"))])
def register(body: RegisterIn, request: Request):
    try:
        auth.create_user(body.email, body.password, "citizen", body.display_name, body.emirate, body.public_rank)
        token, user = auth.login(body.email, body.password, ip_hash(client_ip(request)))
    except auth.AuthError as e:
        raise HTTPException(400, str(e)) from e
    return {"token": token, "user": user}


@router.post("/api/auth/login")
def login(body: LoginIn, request: Request):
    limit, window = LIMITS["login"]  # per address and account, so one attacker can't lock out every officer
    if not limiter.allow(f"login:{ip_hash(client_ip(request))}:{body.email.lower()[:120]}", limit, window):
        raise HTTPException(429, "Too many sign-in attempts. Wait a few minutes and try again.")
    try:
        token, user = auth.login(body.email, body.password, ip_hash(client_ip(request)))
    except auth.AuthError as e:
        audit("login_failed", None, {"email": body.email[:80]})
        raise HTTPException(401, str(e)) from e
    audit("login", user, {"role": user["role"]})
    return {"token": token, "user": user}


@router.post("/api/auth/logout")
def logout(request: Request):
    from .deps import token_of
    if token_of(request):
        auth.logout(token_of(request))
    return {"ok": True}


@router.get("/api/auth/me")
def me(user: dict = Depends(require_user)):
    return user


class UserAdminIn(BaseModel):
    email: str
    password: str
    role: str
    display_name: str | None = None


class UserPatch(BaseModel):
    role: str | None = None
    disabled: bool | None = None


@router.get("/api/admin/users")
def admin_users(user=Depends(require("manage_users"))):
    return auth.list_users()


@router.post("/api/admin/users")
def admin_create(body: UserAdminIn, user=Depends(require("manage_users"))):
    try:
        u = auth.create_user(body.email, body.password, body.role, body.display_name)
    except auth.AuthError as e:
        raise HTTPException(400, str(e)) from e
    audit("user_created", user, {"email": u["email"], "role": u["role"]})
    return u


@router.patch("/api/admin/users/{uid}")
def admin_patch(uid: int, body: UserPatch, user=Depends(require("manage_users"))):
    if uid == user["id"]:
        raise HTTPException(400, "You can’t change your own role or disable yourself")
    if body.role is not None:
        if body.role not in auth.ROLES:
            raise HTTPException(400, "Unknown role")
        db().execute("UPDATE users SET role=? WHERE id=?", (body.role, uid))
    if body.disabled is not None:
        db().execute("UPDATE users SET disabled=? WHERE id=?", (int(body.disabled), uid))
        if body.disabled:
            db().execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    audit("user_changed", user, {"id": uid, **body.model_dump(exclude_none=True)})
    return auth.get_user(uid)


# ============ threat intelligence (RAQEEB Command) ============
@router.get("/api/threats")
def threats(q: str = "", status: str | None = None, category: str | None = None, user=Depends(require("view_investigations"))):
    return intel.search(q, status, category)


@router.get("/api/threats/{tid}")
def threat(tid: str, user=Depends(require("view_investigations"))):
    t = intel.get(tid)
    if not t:
        raise HTTPException(404, "No threat with that ID")
    t["notes"] = rows(db().execute("SELECT author, note, created FROM investigation_notes WHERE threat_id=? ORDER BY created", (tid,)))
    reps = community.reports_for(tid)
    t["reports"] = [{"ref": r["ref"], "type": r["type"], "status": r["status"], "emirate": r["emirate"], "created": r["created"],
                     "text": r["raw_text"][:600], "has_attachment": bool(r["attachment"]),
                     "attachment": json.loads(r["attachment"])["id"] if r["attachment"] and auth.can(user["role"], "view_evidence") else None,
                     "impact": json.loads(r["impact"] or "{}")} for r in reps]
    t["findings"] = rows(db().execute("SELECT agent, confidence, reasoning, source, next_action, created FROM findings WHERE subject IN (?,?) ORDER BY created DESC LIMIT 20",
                                      (t["original"][:300], t["normalized"])))
    t["policy"] = {"can_block_globally": t["status"] == "confirmed_malicious", "scope": protection.scope_for(t)}
    if not auth.can(user["role"], "view_evidence"):
        t["evidence"] = {"redacted": True}
    return t


class ThreatIn(BaseModel):
    indicator: str
    indicator_type: str = "url"
    category: str | None = None
    note: str = ""


@router.post("/api/threats")
def threat_create(body: ThreatIn, user=Depends(require("verify_threat"))):
    if body.indicator_type not in ("url", "domain", "phone", "email", "qr", "text"):
        raise HTTPException(400, "Unknown indicator type")
    risk, brand, ev = 50.0, "", {"added_by": user["email"], "note": body.note[:300]}
    if body.indicator_type in ("url", "domain", "qr"):
        r = scan_many([body.indicator])[0]
        risk, brand = r["risk_score"], (r.get("impersonated_brand") or {}).get("name", "")
        ev["reasons"] = [x["en"] for x in r["reasons"][:4]]
    if body.indicator_type == "phone" and not intel.normalize_phone(body.indicator):
        raise HTTPException(400, "That doesn’t look like a phone number")
    cat = body.category or intel.category_for(body.indicator_type, agents.brand_sector(brand), None)
    t, created = intel.upsert(body.indicator_type, body.indicator, cat, brand, risk, risk / 100, ev, None,
                              source=f"analyst:{user['email']}", actor=user["email"])
    audit("threat_added", user, {"id": t["id"], "created": created})
    return t


class StatusIn(BaseModel):
    status: str
    note: str = ""


@router.post("/api/threats/{tid}/status")
async def threat_status(tid: str, body: StatusIn, user=Depends(require("verify_threat"))):
    allowed = {"under_review", "analyst_verified", "confirmed_malicious", "rejected", "false_positive", "duplicate", "resolved"}
    if body.status not in allowed:
        raise HTTPException(400, "Choose a review decision")
    if not intel.get(tid):
        raise HTTPException(404, "No threat with that ID")
    if body.status == "confirmed_malicious" and not auth.can(user["role"], "approve_threat"):
        raise HTTPException(403, "Analysts verify threats. Official approval needs a Police or Super Administrator.")
    t = community.review(tid, body.status, user, body.note)
    audit("threat_status", user, {"id": tid, "status": body.status, "note": body.note[:200]})
    await hub.send("threat", {"id": tid, "status": t["status"], "status_label": t["status_label"]})
    for r in community.reports_for(tid):
        if r["user_id"]:
            await hub.send("report_status", {"ref": r["ref"], "status": t["status"]}, audience=r["user_id"])
    return t


class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


@router.post("/api/threats/{tid}/notes")
def threat_note(tid: str, body: NoteIn, user=Depends(require("edit_investigation"))):
    db().execute("INSERT INTO investigation_notes (threat_id, author, note, created) VALUES (?,?,?,?)", (tid, user["email"], body.note, time.time()))
    audit("note", user, {"id": tid})
    return {"ok": True}


class BlockIn(BaseModel):
    expiry_days: int = Field(30, ge=1, le=365)
    note: str = ""


@router.post("/api/threats/{tid}/block")
async def threat_block(tid: str, body: BlockIn, user=Depends(require("approve_block"))):
    try:
        pkg = protection.global_block(tid, user, body.expiry_days, body.note)
    except protection.PolicyError as e:
        raise HTTPException(409, str(e)) from e
    await hub.send("protection", {"version": pkg["payload"]["version"], "rules": len(pkg["payload"]["rules"])}, audience="all")
    return {"version": pkg["payload"]["version"], "threat": intel.get(tid)}


@router.post("/api/threats/{tid}/unblock")
async def threat_unblock(tid: str, body: StatusIn | None = None, user=Depends(require("approve_block"))):
    pkg = protection.unblock(tid, user, (body.note if body else "") or "lifted by approver")
    await hub.send("protection", {"version": pkg["payload"]["version"], "rules": len(pkg["payload"]["rules"])}, audience="all")
    return {"version": pkg["payload"]["version"]}


@router.post("/api/threats/{tid}/evidence")
async def threat_evidence(tid: str, user=Depends(require("view_evidence"))):
    """Collect live evidence (RDAP, hosting, TLS, redirects, screenshot) for a web threat and attach the pack."""
    from raqeeb.evidence import write_pack
    from raqeeb.live import enrich
    t = intel.get(tid)
    if not t or t["indicator_type"] not in ("url", "domain", "qr"):
        raise HTTPException(400, "Live evidence is collected for website threats")
    r = scan_many(["http://" + t["normalized"]])[0]
    try:
        r = await asyncio.to_thread(enrich, r, EVIDENCE)
    except Exception as e:  # noqa: BLE001 - offline: still produce a pack from the offline analysis
        r["live"] = {"error": str(e)[:200]}
    folder = Path(r["evidence_pack"]) if r.get("evidence_pack") else write_pack(r, "", None, EVIDENCE)
    intel.add_history(tid, {"event": "evidence_collected", "by": user["email"], "case_id": folder.name})
    db().execute("UPDATE threats SET evidence=json_set(COALESCE(evidence,'{}'), '$.case_id', ?, '$.live', json(?)) WHERE id=?",
                 (folder.name, json.dumps(r.get("live", {}), default=str), tid))
    audit("evidence", user, {"id": tid, "case": folder.name})
    return {"case_id": folder.name, "live": r.get("live", {})}


@router.get("/api/threats/{tid}/export")
def threat_export(tid: str, user=Depends(require("view_evidence"))):
    """Takedown / case export: the full threat record with history, linked reports and findings, as JSON."""
    t = threat(tid, user)
    t["exported_by"], t["export_note"] = user["email"], "Prepared by RAQEEB for review by authorised officers."
    audit("export", user, {"id": tid})
    return Response(json.dumps(t, ensure_ascii=False, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{tid}.json"'})


@router.get("/api/uploads/{upload_id}")
def upload_view(upload_id: str, user=Depends(require("view_evidence"))):
    try:
        return Response(read_image(upload_id), media_type="image/png", headers={"Cache-Control": "no-store"})
    except (BadUpload, FileNotFoundError) as e:
        raise HTTPException(404, "Not found") from e


@router.get("/api/command/overview")
def overview(user=Depends(require_official)):
    q = lambda sql, *a: db().execute(sql, a).fetchone()[0]  # noqa: E731
    day = time.time() - 86400
    return {
        "new_today": q("SELECT COUNT(*) FROM threats WHERE first_seen >= ?", day),
        "under_review": q("SELECT COUNT(*) FROM threats WHERE status IN ('under_review','new','analysing')"),
        "corroborated": q("SELECT COUNT(*) FROM threats WHERE status='community_corroborated'"),
        "confirmed": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious'"),
        "blocked": q("SELECT COUNT(*) FROM threats WHERE block_status='global'"),
        "awaiting_block": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious' AND block_status!='global'"),
        "reports_today": q("SELECT COUNT(*) FROM citizen_reports WHERE created >= ?", day),
        "campaigns": q("SELECT COUNT(DISTINCT campaign_id) FROM threats WHERE campaign_id IS NOT NULL"),
        "by_category": rows(db().execute("SELECT category, COUNT(*) n FROM threats GROUP BY category ORDER BY n DESC")),
        "by_brand": rows(db().execute("SELECT brand, COUNT(*) n FROM threats WHERE brand != '' GROUP BY brand ORDER BY n DESC LIMIT 8")),
        "by_status": rows(db().execute("SELECT status, COUNT(*) n FROM threats GROUP BY status")),
        "protection_version": q("SELECT COALESCE(MAX(version),0) FROM protection_versions"),
        "suspicious_domains_today": q("SELECT COUNT(DISTINCT host) FROM feed WHERE ts >= ? AND risk >= 35", day),
        "lookalikes": q("SELECT COUNT(*) FROM threats WHERE indicator_type IN ('url','domain','qr') AND brand != '' AND status NOT IN ('rejected','false_positive')"),
        "known_malicious": q("SELECT COUNT(*) FROM threats WHERE status IN ('analyst_verified','confirmed_malicious')"),
        "analyst_verified": q("SELECT COUNT(*) FROM threats WHERE status='analyst_verified'"),
        "reports_awaiting": q("SELECT COUNT(*) FROM citizen_reports WHERE status IN ('under_review','analysing','new','community_corroborated')"),
        "active_seasons": [p["season"] for p in agents.seasonal_agent()["predicted"] if p.get("basis") == "seasonal pattern"],
        "demo_records": q("SELECT COUNT(*) FROM threats WHERE demo=1"),
    }


@router.get("/api/command/activity")
def activity(user=Depends(require_official)):
    """Live intelligence activity, built only from recorded events (findings, reviews, publications, reports)."""
    items = []
    for f in rows(db().execute("""SELECT agent, subject, confidence, reasoning, source, created FROM findings
                                  WHERE agent != 'intelligence_briefing' ORDER BY created DESC LIMIT 25""")):
        items.append({"kind": "finding", "ts": f["created"], "demo": (f["source"] or "").startswith("DEMO"),
                      "title": f"{f['agent'].replace('_', ' ').capitalize()}: {f['subject'][:80]}", "detail": f["reasoning"][:200]})
    for a in rows(db().execute("""SELECT action, detail, ts, actor FROM audit WHERE action IN
            ('threat_status','protection_publish','rollback','threat_added','evidence','demo_seed') ORDER BY ts DESC LIMIT 25""")):
        d = json.loads(a["detail"]) if (a["detail"] or "").startswith("{") else {}
        if a["action"] == "threat_status":
            title = f"{d.get('id')} marked {intel.STATUS_LABELS.get(d.get('status'), d.get('status'))}"
        elif a["action"] == "protection_publish":
            title = f"Protection v{d.get('version')} published ({d.get('rules')} rules)"
        elif a["action"] == "demo_seed":
            title = "Demo scenario seeded"
        else:
            title = a["action"].replace("_", " ").capitalize() + (f" {d.get('id')}" if d.get("id") else "")
        items.append({"kind": a["action"], "ts": a["ts"], "demo": a["actor"] == "demo-seed" or a["action"] == "demo_seed",
                      "title": title, "detail": f"by {a['actor']}" + (f" · {d.get('notes')}" if d.get("notes") else "")})
    for r in rows(db().execute("""SELECT r.ref, r.type, r.emirate, r.created, r.threat_ids, u.email FROM citizen_reports r
                                  LEFT JOIN users u ON u.id = r.user_id ORDER BY r.created DESC LIMIT 25""")):
        n = len(json.loads(r["threat_ids"] or "[]"))
        items.append({"kind": "report", "ts": r["created"], "demo": (r["email"] or "").endswith("@raqeeb.demo"),
                      "title": f"Citizen report {r['ref']} ({community.REPORT_TYPES.get(r['type'], r['type'])})",
                      "detail": f"{r['emirate'] or 'Emirate not given'} · linked to {n} indicator{'s' if n != 1 else ''}"})
    return sorted(items, key=lambda i: -i["ts"])[:40]


@router.get("/api/intel/graph")
def graph(user=Depends(require("view_investigations"))):
    return agents.correlate()


@router.get("/api/intel/geography")
def geography(user=Depends(require_official)):
    return content.geography()


@router.get("/api/intel/briefing")
def briefing(period: str = "day", user=Depends(require_official)):
    return agents.briefing_agent(period if period in ("day", "week", "month") else "day")


@router.get("/api/intel/forecast")
def forecast_intel(user=Depends(require_official)):
    from raqeeb.scamcast import forecast
    return agents.seasonal_agent() | {"scamcast": forecast()}


@router.get("/api/intel/findings")
def findings(agent: str | None = None, user=Depends(require("view_investigations"))):
    sql, a = "SELECT * FROM findings", []
    if agent:
        sql += " WHERE agent=?"
        a.append(agent)
    return rows(db().execute(sql + " ORDER BY created DESC LIMIT 200", a))


@router.get("/api/intel/agents")
def agent_list(user=Depends(require_official)):
    counts = dict(db().execute("SELECT agent, COUNT(*) FROM findings GROUP BY agent").fetchall())
    return [{"id": a, "findings": counts.get(a, 0)} for a in agents.AGENTS] + [{"llm_enabled": bool(agents.os.environ.get("RAQEEB_LLM_URL"))}]


@router.get("/api/intel/early-watch")
def early_watch(user=Depends(require("view_investigations"))):
    """Suspicious look-alike domains found by the threat hunter that are not yet threat records."""
    known = {r[0] for r in db().execute("SELECT normalized FROM threats")}
    out = []
    for f in rows(db().execute("SELECT * FROM feed WHERE ts > 0 AND risk >= 35 ORDER BY ts DESC LIMIT 300")):
        host = f["host"].removeprefix("www.")
        if host not in known and not any(k.startswith(host + "/") for k in known):
            out.append(f)
    return out


class PromoteIn(BaseModel):
    url: str
    note: str = ""


@router.post("/api/intel/early-watch/promote")
def promote(body: PromoteIn, user=Depends(require("verify_threat"))):
    return threat_create(ThreatIn(indicator=body.url, indicator_type="url", note=body.note or "promoted from early threat watch"), user)


@router.get("/api/intel/queue")
def block_queue(user=Depends(require("approve_block"))):
    return agents.distribution_agent()


@router.get("/api/intel/impact")
def impact(user=Depends(require_official)):
    return content.impact()


@router.get("/api/audit")
def audit_log(limit: int = 300, user=Depends(require("view_audit"))):
    return rows(db().execute("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (min(limit, 2000),)))


@router.get("/api/reports/queue")
def reports_queue(status: str | None = None, user=Depends(require("view_investigations"))):
    out = community.queue(status)
    for r in out:
        r.pop("ip_hash", None)
        if not auth.can(user["role"], "view_evidence") and r.get("attachment"):
            r["attachment"] = {"redacted": True}
    return out


@router.get("/api/community/abuse")
def abuse(user=Depends(require("review_community"))):
    """Accounts whose reporting patterns need a look: many reports in a day, many rejections, low reputation."""
    day = time.time() - 86400
    return rows(db().execute("""SELECT u.id, u.display_name, u.emirate, u.reputation,
        (SELECT COUNT(*) FROM citizen_reports r WHERE r.user_id=u.id AND r.created >= ?) reports_24h,
        (SELECT COUNT(*) FROM citizen_reports r WHERE r.user_id=u.id AND r.status IN ('rejected','false_positive')) rejected,
        (SELECT COUNT(*) FROM citizen_reports r WHERE r.user_id=u.id) total
        FROM users u WHERE u.role='citizen' AND (u.reputation < 0.7 OR rejected >= 2 OR reports_24h >= 15) ORDER BY u.reputation""", (day,)))


# ============ protection distribution ============
@router.get("/api/protection/latest")
def protection_latest():
    return protection.latest()


@router.get("/api/protection/public-key")
def protection_key():
    return {"algorithm": "Ed25519", "public_key": protection.public_key_b64()}


@router.get("/api/protection/versions")
def protection_versions(user=Depends(require_official)):
    return protection.versions()


@router.post("/api/protection/rollback")
async def protection_rollback(user=Depends(require("rollback"))):
    try:
        pkg = protection.rollback(user)
    except protection.PolicyError as e:
        raise HTTPException(409, str(e)) from e
    audit("rollback", user, {"version": pkg["payload"]["version"]})
    await hub.send("protection", {"version": pkg["payload"]["version"], "rules": len(pkg["payload"]["rules"])}, audience="all")
    return {"version": pkg["payload"]["version"]}


@router.get("/api/protection/check", dependencies=[Depends(rate("check"))])
def protection_check(value: str, kind: str = "url", user=Depends(current_user)):
    content.bump("checks")
    hit = protection.check_value(value, kind)
    personal = False
    if not hit and user:
        target = intel.normalize_phone(value) if kind == "phone" else intel.normalize("domain", value)
        personal = community.personally_blocked(user["id"], target or value)
    if hit:
        content.bump("checks_blocked")
    return {"blocked": bool(hit), "rule": hit, "personal": personal}


# ============ citizens: RAQEEB Protect ============
@router.post("/api/citizen/report", dependencies=[Depends(rate("report"))])
async def citizen_report(request: Request, type: str = Form("auto"), text: str = Form(""), emirate: str | None = Form(None),
                         impact: str = Form("{}"), file: UploadFile | None = File(None), user=Depends(current_user)):
    if emirate and emirate not in auth.EMIRATES:
        raise HTTPException(400, "Choose one of the seven emirates")
    if type != "auto" and type not in community.REPORT_TYPES:
        raise HTTPException(400, "Choose a report type")
    attachment, ocr = None, ""
    if file is not None and file.filename:
        data = await file.read(5 * 1024 * 1024 + 1)
        try:
            attachment = store_image(data)
        except BadUpload as e:
            raise HTTPException(400, str(e)) from e
        ocr = await asyncio.to_thread(ocr_image, attachment["id"])
    if not text.strip() and not attachment:
        raise HTTPException(400, "Paste the message, link or number, or attach a screenshot")
    try:
        imp = json.loads(impact or "{}")
    except json.JSONDecodeError:
        imp = {}
    r = await asyncio.to_thread(community.submit, user, type, text, emirate or (user or {}).get("emirate"), attachment,
                                imp if isinstance(imp, dict) else {}, ip_hash(client_ip(request)), ocr)
    await hub.send("citizen_report", {"ref": r["ref"], "type": r["type"], "risk": r["risk"], "severity": r["severity"],
                                      "emirate": emirate, "threats": r["threat_refs"]})
    if r["risk"] and r["risk"] >= 50:
        for link in r["links"]:
            await hub.send("feed", {"url": link["url"], "risk": link["risk"], "verdict": link["verdict"], "brand": link["brand"] or "",
                                    "source": "Citizen report (RAQEEB Protect)", "reason": r["explanation_en"][:160]})
    return r


@router.get("/api/citizen/reports")
def citizen_reports(user=Depends(require_user)):
    return community.my_reports(user["id"])


@router.get("/api/citizen/reports/{ref}")
def citizen_report_view(ref: str, user=Depends(require_user)):
    r = community.get_report(ref)
    if not r or r["user_id"] != user["id"]:
        raise HTTPException(404, "No report with that reference")
    return community.citizen_view(r)


class CorroborateIn(BaseModel):
    threat_id: str


@router.post("/api/citizen/corroborate", dependencies=[Depends(rate("corroborate"))])
def citizen_corroborate(body: CorroborateIn, user=Depends(require_user)):
    try:
        return community.corroborate(user, body.threat_id)
    except KeyError as e:
        raise HTTPException(404, "Unknown threat") from e


class ValueIn(BaseModel):
    value: str = Field(min_length=3, max_length=500)


@router.post("/api/citizen/blocks")
def citizen_block(body: ValueIn, user=Depends(require_user)):
    """'Block for me': affects only this citizen's own protection. Nothing is blocked for anyone else."""
    return community.block_for_me(user, body.value)


@router.get("/api/citizen/blocks")
def citizen_blocks(user=Depends(require_user)):
    return community.my_blocks(user["id"])


@router.delete("/api/citizen/blocks")
def citizen_unblock(value: str, user=Depends(require_user)):
    community.unblock_for_me(user["id"], value)
    return {"ok": True}


@router.get("/api/citizen/profile")
def citizen_profile(user=Depends(require_user)):
    return {"user": user, **rewards.profile(user["id"]), "family": community.my_family(user["id"]),
            "learning": dict(db().execute("SELECT sim_id, correct FROM learning WHERE user_id=?", (user["id"],)).fetchall())}


class ProfilePatch(BaseModel):
    display_name: str | None = None
    emirate: str | None = None
    public_rank: bool | None = None


@router.patch("/api/citizen/profile")
def citizen_profile_patch(body: ProfilePatch, user=Depends(require_user)):
    if body.display_name is not None:
        name = re.sub(r"[<>]", "", body.display_name).strip()[:40] or auth.anonymous_name()
        db().execute("UPDATE users SET display_name=? WHERE id=?", (name, user["id"]))
    if body.emirate is not None:
        if body.emirate not in auth.EMIRATES:
            raise HTTPException(400, "Choose one of the seven emirates")
        db().execute("UPDATE users SET emirate=? WHERE id=?", (body.emirate, user["id"]))
    if body.public_rank is not None:
        db().execute("UPDATE users SET public_rank=? WHERE id=?", (int(body.public_rank), user["id"]))
    return auth.get_user(user["id"])


@router.get("/api/citizen/notifications")
def citizen_notifications(user=Depends(require_user)):
    return community.my_notifications(user["id"])


class FamilyIn(BaseModel):
    name: str = "My family"


class JoinIn(BaseModel):
    code: str


class ShareIn(BaseModel):
    title: str = Field(max_length=120)
    body: str = Field(max_length=600)


@router.post("/api/citizen/family")
def family_create(body: FamilyIn, user=Depends(require_user)):
    if community.my_family(user["id"]):
        raise HTTPException(409, "You’re already in a family group")
    return community.create_family(user, body.name)


@router.post("/api/citizen/family/join")
def family_join(body: JoinIn, user=Depends(require_user)):
    try:
        return community.join_family(user, body.code)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/api/citizen/family/share")
def family_share(body: ShareIn, user=Depends(require_user)):
    try:
        return {"sent_to": community.share_with_family(user, body.title, body.body)}
    except KeyError as e:
        raise HTTPException(400, str(e)) from e


class AnswerIn(BaseModel):
    scam: bool


@router.post("/api/learn/simulations/{sim_id}")
def learn_answer(sim_id: str, body: AnswerIn, user=Depends(current_user)):
    try:
        res = content.answer_simulation(sim_id, body.scam)
    except KeyError as e:
        raise HTTPException(404, "Unknown simulation") from e
    res["points"] = 0
    if user:
        first = db().execute("INSERT OR IGNORE INTO learning (user_id, sim_id, correct, created) VALUES (?,?,?,?)",
                             (user["id"], sim_id, int(res["correct"]), time.time())).rowcount == 1
        today = db().execute("SELECT COALESCE(SUM(delta),0) FROM points WHERE user_id=? AND kind='learning' AND created >= ?",
                             (user["id"], time.time() - 86400)).fetchone()[0]
        if first and res["correct"] and today < 20:  # learning points are capped so they can't be farmed
            db().execute("INSERT OR IGNORE INTO points (user_id, delta, reason, threat_id, kind, explanation, created) VALUES (?,?,?,?,?,?,?)",
                         (user["id"], rewards.POINTS["learning"], "learning", sim_id, "learning", rewards.EXPLAIN["learning"], time.time()))
            res["points"] = rewards.POINTS["learning"]
    return res


# ============ public ============
@router.get("/api/public/alerts")
def public_alerts():
    return content.public_alerts()


@router.get("/api/public/leaderboard")
def public_leaderboard(period: str = "week", emirate: str | None = None):
    if emirate and emirate not in auth.EMIRATES:
        raise HTTPException(400, "Unknown emirate")
    return {"guardians": rewards.leaderboard(period, emirate), "emirates": rewards.emirate_ranking(period if period != "all" else "all")}


@router.get("/api/public/brands")
def public_brands():
    return content.brand_registry()


@router.get("/api/public/knowledge")
def public_knowledge():
    return {"articles": content.KNOWLEDGE, "simulations": content.simulations_public()}


@router.get("/api/public/safety-report")
def public_safety(days: int = 30):
    return content.safety_report(max(1, min(days, 365)))


@router.get("/api/public/forecast")
def public_forecast():
    s = agents.seasonal_agent()
    return {"predicted": s["predicted"], "note": s["note"]}


@router.get("/api/public/meta")
def public_meta():
    return {"report_types": community.REPORT_TYPES, "emirates": auth.EMIRATES, "levels": rewards.LEVELS,
            "points": rewards.POINTS, "badges": rewards.BADGES, "statuses": intel.STATUS_LABELS, "categories": intel.CATEGORIES}


@router.get("/api/preview", dependencies=[Depends(rate("check"))])
async def link_preview(url: str):
    """Safe link preview: follow redirects server-side (never to internal addresses) and show where a link really goes,
    without the user opening it. The page is fetched as text only; no scripts run."""
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    first = scan_many([url])[0]
    out = {"url": url, "risk": first["risk_score"], "verdict": first["verdict"], "reasons": first["reasons"][:4],
           "brand": (first.get("impersonated_brand") or {}).get("name")}
    try:
        resp, chain, text = await asyncio.to_thread(safe_get, url, {"User-Agent": "Mozilla/5.0 RAQEEB-preview"}, 6, 6)
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        out["final_url"], out["chain"], out["title"] = resp.url, chain, (m.group(1).strip()[:160] if m else None)
        if resp.url != url:
            final = scan_many([resp.url])[0]
            out["final_risk"], out["final_verdict"] = final["risk_score"], final["verdict"]
            out["risk"] = max(out["risk"], final["risk_score"])
    except UnsafeTarget as e:
        out["error"] = f"Not fetched: {e}"
    except Exception:  # noqa: BLE001 - offline or the site refused: the offline verdict still stands
        out["error"] = "The site could not be reached for a preview. The offline check above still applies."
    return out



# ============ citizen tools: assistant, phone and advert checks, translation, emergency guidance ============
class AskIn(BaseModel):
    message: str = Field(min_length=1, max_length=3000)
    lang: str | None = None


@router.post("/api/assistant", dependencies=[Depends(rate("check"))])
def assistant_ask(body: AskIn):
    from raqeeb import assistant
    return assistant.answer(body.message, body.lang)


@router.get("/api/public/check-phone", dependencies=[Depends(rate("check"))])
def check_phone(number: str, user=Depends(current_user)):
    """What RAQEEB knows about a number. One citizen report never makes a number 'malicious'."""
    n = intel.normalize_phone(number)
    if not n:
        raise HTTPException(400, "That doesn’t look like a phone number")
    info, _ = agents.phone_agent(n)
    rule = protection.check_value(n, "phone")
    t = rows(db().execute("SELECT status, report_count FROM threats WHERE indicator_type='phone' AND normalized=?", (n,)))
    status = t[0]["status"] if t else None
    verdict = ("blocked" if rule else "confirmed" if status == "confirmed_malicious" else "verified" if status == "analyst_verified"
               else "reported" if t else "unknown")
    return {"number": n, "kind": info["kind"], "verdict": verdict, "reports": t[0]["report_count"] if t else 0, "status": status,
            "signals": info["signals"], "personal_block": bool(user and community.personally_blocked(user["id"], n)),
            "note": "Reports alone don’t prove a number is a scam. A number is only marked as a scam after analysts verify it."}


@router.post("/api/public/check-ad", dependencies=[Depends(rate("check"))])
async def check_ad(text: str = Form(""), file: UploadFile | None = File(None)):
    """Analyse an advertisement's text and, if Tesseract is installed, the text in its screenshot. Nothing is stored."""
    ocr_text, ocr_state = "", "no screenshot"
    if file is not None and file.filename:
        import io
        from PIL import Image, UnidentifiedImageError
        data = await file.read(5 * 1024 * 1024 + 1)
        if len(data) > 5 * 1024 * 1024:
            raise HTTPException(400, "Images must be under 5 MB")
        try:
            img = Image.open(io.BytesIO(data))
            img.verify()
            img = Image.open(io.BytesIO(data)).convert("RGB")
        except (UnidentifiedImageError, OSError) as e:
            raise HTTPException(400, "That file isn’t a readable image") from e
        from raqeeb.link.visual import ocr
        o = await asyncio.to_thread(ocr, img)
        ocr_text, ocr_state = (o.get("text", ""), "read") if o.get("available") else ("", "OCR not installed on this server")
    full = (text + "\n" + ocr_text).strip()
    if not full:
        raise HTTPException(400, "Paste the advert text or attach a screenshot")
    ex = agents.extract(full)
    links, _ = agents.phishing_agent(ex["urls"])
    ad, _ = agents.ad_agent(full, links)
    msg = check_message(full)
    risk = max(ad["risk"], msg["risk_score"])
    return {"risk": round(risk, 1), "verdict": "scam" if risk >= 50 else "suspicious" if risk >= 35 else "no strong signs",
            "signals": ad["signals"], "script_signals": msg["script_signals"], "brands_named": msg["brands_named"],
            "links": [{"url": l["url"], "risk": l["risk_score"], "verdict": l["verdict"], "brand": (l.get("impersonated_brand") or {}).get("name")} for l in links],
            "phones": ex["phones"], "ocr": ocr_state, "extracted_text": ocr_text[:1500]}


class TranslateIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    target: str = Field(pattern="^(en|ar|ur)$")


@router.post("/api/translate", dependencies=[Depends(rate("check"))])
def translate_text(body: TranslateIn):
    from raqeeb import translate
    return translate.translate(body.text, body.target)


@router.get("/api/public/emergency")
def emergency():
    return content.EMERGENCY


class DetailsIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@router.post("/api/citizen/reports/{ref}/details")
def report_details(ref: str, body: DetailsIn, user=Depends(require_user)):
    """Add more details to your own report after sending it (for example after a Quick Alert)."""
    r = community.get_report(ref)
    if not r or r["user_id"] != user["id"]:
        raise HTTPException(404, "No report with that reference")
    prev = json.loads(db().execute("SELECT details FROM citizen_reports WHERE id=?", (r["id"],)).fetchone()[0] or "[]")
    prev.append({"text": body.text, "ts": time.time()})
    db().execute("UPDATE citizen_reports SET details=?, updated=? WHERE id=?", (json.dumps(prev[-20:]), time.time(), r["id"]))
    ex = agents.extract(body.text)
    if ex["urls"] or ex["phones"]:  # new indicators in the details go through the normal pipeline, linked to the same report
        community.submit(user, "other", body.text, r["emirate"])
    return {"ref": ref, "details": len(prev)}
