"""SAWNN demonstration sign-in prototype (a national-digital-identity *style* flow) and its security simulator.

This is SIMULATED. It is not UAE PASS, does not talk to UAE PASS, and never asks for or accepts real UAE PASS
credentials, Emirates ID numbers or OTPs. The "QR code" carries a SAWNN demo request ID; the "phone approval" is a
button on the demo page. It only works while the server runs in demo mode (SAWNN_DEMO=1) and only signs in to SAWNN's
own demo accounts. The real, authorised integration path is documented in docs/UAE_PASS_INTEGRATION.md.
"""
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from raqeeb import auth, demo_scenario
from raqeeb.db import db, one

from .deps import client_ip

router = APIRouter(prefix="/api/signin-demo", tags=["Demo sign-in prototype (simulated)"])
TTL = 120
_requests: dict[str, dict] = {}
ACCOUNTS = {"citizen": "citizen@sawnn.demo", "analyst": "analyst@sawnn.demo", "admin": "admin@sawnn.demo"}


def _gc():
    now = time.time()
    for k in [k for k, v in _requests.items() if v["expires"] < now - 600]:
        _requests.pop(k, None)


def _need_demo():
    if not demo_scenario.enabled():
        raise HTTPException(403, "The demonstration sign-in only works when the server runs in demo mode (SAWNN_DEMO=1).")


@router.post("/start")
def start():
    _need_demo()
    _gc()
    rid = secrets.token_urlsafe(9)
    _requests[rid] = {"state": "waiting", "expires": time.time() + TTL, "account": None, "consent": None, "claimed": False}
    return {"request_id": rid, "qr_payload": f"SAWNN-DEMO-SIGNIN:{rid}", "expires_in": TTL, "simulated": True}


class ApproveIn(BaseModel):
    account: str = Field(pattern="^(citizen|analyst|admin)$")
    approve: bool
    consent: bool = False


@router.post("/{rid}/respond")
def respond(rid: str, body: ApproveIn):
    """Stands in for the user approving on their phone. In the real service this happens in the identity app."""
    _need_demo()
    r = _requests.get(rid)
    if not r or r["expires"] < time.time():
        raise HTTPException(410, "This sign-in request has expired. Start again.")
    if r["state"] != "waiting":
        raise HTTPException(409, "This request has already been answered.")
    if body.approve and not body.consent:
        raise HTTPException(400, "Consent to share the demo profile with SAWNN is required to continue.")
    r.update(state="approved" if body.approve else "denied", account=body.account, consent=body.consent)
    return {"state": r["state"]}


@router.get("/{rid}")
def poll(rid: str, request: Request):
    _need_demo()
    r = _requests.get(rid)
    if not r:
        raise HTTPException(404, "Unknown request")
    if r["state"] == "waiting" and r["expires"] < time.time():
        r["state"] = "expired"
    out = {"state": r["state"], "expires_in": max(0, int(r["expires"] - time.time())), "simulated": True}
    if r["state"] == "approved" and not r["claimed"]:
        u = one(db().execute("SELECT id FROM users WHERE email = ?", (ACCOUNTS[r["account"]],)))
        if not u:
            raise HTTPException(500, "Demo accounts are missing; restart with SAWNN_DEMO=1")
        token, user = auth.issue_session(u["id"], client_ip(request))
        db().execute("INSERT INTO audit (action, detail, ts, actor) VALUES (?,?,?,?)",
                     ("demo_signin", '{"method": "simulated identity prototype"}', time.time(), user["email"]))
        db().commit()
        r["claimed"] = True  # one-time: the token is handed out once and the request cannot be replayed
        out.update(token=token, app="command" if user["role"] in auth.OFFICIAL_ROLES else "app",
                   user={"display_name": user["display_name"], "role": user["role_name"]})
    return out
