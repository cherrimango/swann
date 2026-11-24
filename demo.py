"""Rehearsal data for a live demo. Fills an empty MIRA instance through its own API, exactly as real users would:

  * registers demo citizens (emails end in @mira.demo, so they are easy to spot and delete),
  * submits citizen reports built from REAL UAE-targeted scam URLs mined from public phishing feeds,
  * has demo citizens corroborate some of them, and an analyst verify and confirm a few.

Nothing here is presented as operational data: every account and report it creates is a demo account or report.

    python demo.py --api http://localhost:8000 --admin-password <from data/first_run_credentials.txt>
"""
import argparse
import csv
import random
import re
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
EMIRATES = ["Abu Dhabi", "Dubai", "Sharjah", "Ajman", "Umm Al Quwain", "Ras Al Khaimah", "Fujairah"]
TEMPLATES = {
    "sms": "{brand}: your account needs urgent verification today or it will be suspended. Continue: {url}",
    "whatsapp": "Hello, this is {brand} customer care. Your delivery/payment is on hold. Complete it here within 2 hours: {url}",
    "email": "From: {brand} Security <support@{brand_slug}-alerts.mail>\nSubject: Action required\nPlease confirm your details at {url}",
    "website": "{url}",
}
PHONES = ["+971501234567", "+971552220131", "+97143316600", "+447700900123"]


def admin_password(arg: str | None) -> str:
    if arg:
        return arg
    creds = ROOT / "data" / "first_run_credentials.txt"
    m = re.search(r"admin@raqeeb\.local\s+(\S+)", creds.read_text()) if creds.exists() else None
    if not m:
        raise SystemExit("Pass --admin-password (see data/first_run_credentials.txt)")
    return m.group(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--admin-password")
    ap.add_argument("--reports", type=int, default=20)
    a = ap.parse_args()
    rnd = random.Random(7)
    s = requests.Session()

    def post(path, token=None, **kw):
        r = s.post(a.api + path, headers={"Authorization": f"Bearer {token}"} if token else {}, timeout=60, **kw)
        r.raise_for_status()
        return r.json()

    citizens = []
    for i in range(5):  # the server allows 5 sign-ups per address per hour
        email = f"demo{i}@mira.demo"
        r = s.post(a.api + "/api/auth/register", json={"email": email, "password": "demo-password-1", "emirate": EMIRATES[i % 7],
                                                        "public_rank": i != 3}, timeout=30)
        if r.status_code == 400:  # already registered on an earlier run
            r = s.post(a.api + "/api/auth/login", json={"email": email, "password": "demo-password-1"}, timeout=30)
        r.raise_for_status()
        citizens.append(r.json()["token"])
    admin = post("/api/auth/login", json={"email": "admin@mira.local", "password": admin_password(a.admin_password)})["token"]

    rows = list(csv.DictReader((ROOT / "data" / "uae_scam_urls.csv").open(encoding="utf-8")))
    rnd.shuffle(rows)
    refs = []
    for i, row in enumerate(rows[: a.reports]):
        kind = rnd.choice(list(TEMPLATES))
        text = TEMPLATES[kind].format(brand=row["brand"], brand_slug=row["brand_id"], url=row["url"])
        if kind == "sms" and i % 4 == 0:
            text += f" or call {PHONES[i % len(PHONES)]}"
        tok = citizens[i % len(citizens)]
        r = post("/api/citizen/report", tok, data={"type": kind, "text": text, "emirate": EMIRATES[i % 7],
                                                    "impact": '{"received": true}'})
        refs.append(r)
        if i % 3 == 0:  # two more citizens saw the same link
            for other in (citizens[(i + 1) % 5], citizens[(i + 2) % 5]):
                post("/api/citizen/report", other, data={"type": "website", "text": row["url"], "emirate": EMIRATES[(i + 3) % 7]})
        print(f"{r['ref']}  {r['type']:<9} risk {r['risk']:>5}  {r['threat_refs']}")

    decided = 0
    for r in refs[:6]:
        for tid in r["threat_refs"][:1]:
            post(f"/api/threats/{tid}/status", admin, json={"status": "analyst_verified", "note": "demo review"})
            post(f"/api/threats/{tid}/status", admin, json={"status": "confirmed_malicious", "note": "demo review"})
            if decided < 3:
                post(f"/api/threats/{tid}/block", admin, json={"expiry_days": 30, "note": "demo block"})
            decided += 1
    print(f"\nDemo ready: {len(refs)} reports from {len(citizens)} demo citizens, {decided} threats confirmed, 3 blocked.")


if __name__ == "__main__":
    main()
