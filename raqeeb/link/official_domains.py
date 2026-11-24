"""UAE official brand registry: organisations, their official registered domains and verification status.

Built-in entries come from raqeeb/brands.json. Entries whose domain confidence is 'high' were checked against the
organisation's own website when the profile was written; 'check' entries are unverified candidates. Administrators can
add organisations through the API; those start as unverified until someone records a verification source.
Unverified domains are never used to call a link safe.
"""
import json
import time

from rapidfuzz.distance import Levenshtein

from ..brands import BRANDS, collapse
from ..db import db, rows

BUILTIN_VERIFIED_ON = "2026-11-24"
# Organisations named in the brief that have no detection profile yet. Domains are unverified candidates.
CANDIDATES = [
    {"id": "rakbank", "name": "RAKBANK", "name_ar": "بنك رأس الخيمة الوطني", "sector": "banking", "domains": ["rakbank.ae"]},
    {"id": "sib", "name": "Sharjah Islamic Bank", "name_ar": "مصرف الشارقة الإسلامي", "sector": "banking", "domains": ["sib.ae"]},
    {"id": "virginmobile", "name": "Virgin Mobile UAE", "name_ar": "فيرجن موبايل الإمارات", "sector": "telecom", "domains": ["virginmobile.ae"]},
    {"id": "noon", "name": "Noon", "name_ar": "نون", "sector": "retail", "domains": ["noon.com"]},
    {"id": "amazonae", "name": "Amazon UAE", "name_ar": "أمازون الإمارات", "sector": "retail", "domains": ["amazon.ae"]},
    {"id": "talabat", "name": "Talabat", "name_ar": "طلبات", "sector": "delivery", "domains": ["talabat.com"]},
    {"id": "careem", "name": "Careem", "name_ar": "كريم", "sector": "transport", "domains": ["careem.com"]},
]


def organisations() -> list[dict]:
    out = []
    for b in BRANDS:
        out.append({
            "id": b["id"], "name": b["name"], "name_ar": b["name_ar"], "sector": b["sector"], "origin": "built-in profile",
            "domains": [{"domain": d["domain"], "status": "verified" if d["confidence"] == "high" else "unverified_candidate",
                         "verification_source": "organisation's official website" if d["confidence"] == "high" else None,
                         "verified_on": BUILTIN_VERIFIED_ON if d["confidence"] == "high" else None} for d in b["official_domains"]],
            "brand_keywords": b["keywords"], "detection_profile": True,
        })
    for c in CANDIDATES:
        out.append({"id": c["id"], "name": c["name"], "name_ar": c["name_ar"], "sector": c["sector"], "origin": "built-in candidate",
                    "domains": [{"domain": d, "status": "unverified_candidate", "verification_source": None, "verified_on": None}
                                for d in c["domains"]], "brand_keywords": [c["id"]], "detection_profile": False})
    for o in rows(db().execute("SELECT * FROM organizations ORDER BY name")):
        out.append({"id": o["id"], "name": o["name"], "name_ar": o["name_ar"], "sector": o["sector"], "origin": f"added by {o['added_by']}",
                    "domains": json.loads(o["domains"]), "brand_keywords": json.loads(o["keywords"] or "[]"), "detection_profile": False})
    return out


def add_organisation(data: dict, actor: str) -> dict:
    oid = collapse(data["name"])[:40] or f"org{int(time.time())}"
    domains = [{"domain": d.lower().strip(), "status": "verified" if data.get("verification_source") else "unverified_candidate",
                "verification_source": data.get("verification_source"),
                "verified_on": time.strftime("%Y-%m-%d") if data.get("verification_source") else None}
               for d in data["domains"] if d.strip()]
    db().execute("""INSERT INTO organizations (id, name, name_ar, sector, domains, keywords, added_by, created) VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET domains=excluded.domains, keywords=excluded.keywords, sector=excluded.sector""",
                 (oid, data["name"][:80], (data.get("name_ar") or "")[:80], (data.get("sector") or "other")[:40],
                  json.dumps(domains), json.dumps(data.get("keywords") or []), actor, time.time()))
    return next(o for o in organisations() if o["id"] == oid)


def match(v: dict) -> dict:
    """Compare a validated URL with the registry: official match, brand/domain mismatch, look-alike similarity."""
    host, reg = v["hostname"], v["registered_domain"]
    best = {"official_domain_match": False, "organisation": None, "matched_domain": None, "domain_status": None,
            "subdomain_of_official": False, "closest_official": None, "similarity": 0.0, "brand_keyword_found": None}
    label = collapse(v["domain_label"] or "")
    for o in organisations():
        for d in o["domains"]:
            dom = d["domain"]
            if host == dom or host.endswith("." + dom):
                if d["status"] == "verified":
                    return {**best, "official_domain_match": True, "organisation": o["name"], "matched_domain": dom,
                            "domain_status": "verified", "subdomain_of_official": host != dom and host != "www." + dom}
                best.update({"organisation": o["name"], "matched_domain": dom, "domain_status": "unverified_candidate"})
            sim = 1 - Levenshtein.normalized_distance(reg, dom)
            if sim > best["similarity"] and reg != dom:
                best.update({"closest_official": f"{o['name']} ({dom})", "similarity": round(sim, 3)})
        for k in o["brand_keywords"]:
            ck = collapse(k)
            if len(ck) >= 4 and ck in collapse(host) and not best["brand_keyword_found"]:
                best["brand_keyword_found"] = o["name"]
    if label and best["similarity"] < 0.5:
        best["closest_official"] = None
    return best
