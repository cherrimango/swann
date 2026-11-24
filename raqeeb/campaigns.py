"""Scam DNA: group scam URLs into campaigns by the phishing kit they share.

Scammers change domains daily but reuse the same kit, so the path skeleton
(file names, folder pattern, query keys) is a fingerprint that survives a domain change.
"""
import re
from collections import defaultdict

from .urlparse import parse

_HEX = re.compile(r"^[0-9a-f]{8,}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _norm_segment(seg: str) -> str:
    s = seg.lower()
    if _UUID.match(s):
        return "{uuid}"
    if _HEX.match(s):
        return "{hex}"
    if re.fullmatch(r"\d+", s):
        return "{n}"
    s = re.sub(r"\d{3,}", "{n}", s)
    return s


def kit_signature(url: str) -> str | None:
    """Fingerprint of a URL's path and query keys; None when the path carries no kit pattern."""
    p = parse(url)
    segs = [_norm_segment(s) for s in p.path.split("/") if s]
    keys = sorted({k.split("=")[0].lower() for k in p.query.split("&") if "=" in k})
    if not segs and not keys:
        return None
    tail = segs[-2:]
    if not any(re.search(r"[a-z]", re.sub(r"\{\w+\}", "", t)) for t in tail):
        return None  # only random tokens: no kit fingerprint
    sig = "/" + "/".join(tail)
    if keys:
        sig += "?" + "&".join(keys[:6])
    if sig in ("/", "/index.html", "/index.php") or len(sig) < 6:
        return None
    return sig


def build(rows: list[dict], min_domains: int = 2) -> dict:
    """rows: dicts with url, registered_domain, brand. Returns campaigns plus a node/edge graph."""
    by_sig = defaultdict(list)
    for r in rows:
        sig = kit_signature(r["url"])
        if sig:
            by_sig[sig].append(r)
    campaigns = []
    for sig, items in by_sig.items():
        domains = sorted({i["registered_domain"] for i in items})
        if len(domains) < min_domains:
            continue
        brands = sorted({i["brand"] for i in items})
        campaigns.append({"id": f"C{len(campaigns) + 1:03d}", "kit_signature": sig, "domains": domains,
                          "brands": brands, "url_count": len(items), "sample_urls": [i["url"] for i in items[:5]]})
    campaigns.sort(key=lambda c: (-len(c["domains"]), -c["url_count"]))
    for i, c in enumerate(campaigns):
        c["id"] = f"C{i + 1:03d}"
    nodes, edges, seen = [], [], set()

    def node(nid, kind, label):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": label})

    for c in campaigns:
        kid = "kit:" + c["id"]
        node(kid, "kit", c["kit_signature"])
        for b in c["brands"]:
            node("brand:" + b, "brand", b)
            edges.append({"source": kid, "target": "brand:" + b})
        for d in c["domains"]:
            node("domain:" + d, "domain", d)
            edges.append({"source": "domain:" + d, "target": kid})
    return {"campaigns": campaigns, "graph": {"nodes": nodes, "edges": edges}}
