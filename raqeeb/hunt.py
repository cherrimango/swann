"""Early-detection hunting: look-alike domain generation, DNS checks, certificate-log search, live CT stream."""
import csv
import datetime as dt
import socket
import sys

import requests

from .brands import BRANDS, official_brand
from .engine import scan_many
from .urlparse import parse

LURE_AFFIXES = ["pay", "fines", "fine", "login", "verify", "update", "secure", "online", "portal", "uae", "ae",
                "gov", "services", "toll", "track", "parcel", "refund", "reward", "points", "kyc", "app"]
TLDS = ["com", "net", "org", "info", "online", "site", "top", "xyz", "shop", "live", "click", "icu", "cfd",
        "sbs", "vip", "support", "help", "com.co", "cc", "io", "app"]
HOMO = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"]}
KEYBOARD = {"a": "qsz", "s": "awdz", "d": "sefx", "e": "wrd", "i": "uok", "o": "ipl", "l": "kop", "m": "nk",
            "n": "bm", "t": "ryg", "r": "etf", "p": "ol", "u": "yi", "b": "vn", "c": "xv", "k": "jl"}


def permutations(word: str) -> set[str]:
    out = set()
    for i in range(len(word)):
        out.add(word[:i] + word[i + 1:])                                   # omission
        out.add(word[:i] + word[i] + word[i:])                             # repetition
        if i < len(word) - 1:
            out.add(word[:i] + word[i + 1] + word[i] + word[i + 2:])       # transposition
        for r in HOMO.get(word[i], []):
            out.add(word[:i] + r + word[i + 1:])                           # homoglyph
        for r in KEYBOARD.get(word[i], ""):
            out.add(word[:i] + r + word[i + 1:])                           # fat-finger
        if 0 < i < len(word):
            out.add(word[:i] + "-" + word[i:])                             # hyphenation
    out.discard(word)
    return {w for w in out if len(w) >= 3}


def candidates(brand: dict, max_per_brand: int) -> list[str]:
    base = [k.replace("-", "") for k in brand["keywords"] if len(k.replace("-", "")) >= 4][:2]
    names = set()
    for b in base:
        for a in LURE_AFFIXES:
            names |= {f"{b}-{a}", f"{a}-{b}", f"{b}{a}"}
        names |= permutations(b)
        names.add(b)
    doms = [f"{n}.{t}" for n in sorted(names) for t in TLDS]
    doms = [d for d in doms if not official_brand(parse(d))]
    return doms[:max_per_brand]


def resolves(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def crtsh(days: int, keywords: list[str]) -> list[str]:
    since = dt.datetime.utcnow() - dt.timedelta(days=days)
    found = set()
    for kw in keywords:
        try:
            rows = requests.get("https://crt.sh/", params={"q": f"%{kw}%", "output": "json"}, timeout=60).json()
        except Exception as e:  # noqa: BLE001
            print(f"crt.sh {kw}: {e}", file=sys.stderr)
            continue
        for r in rows:
            try:
                if dt.datetime.fromisoformat(r["not_before"]) < since:
                    continue
            except (KeyError, ValueError):
                continue
            for name in r.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if kw in name and not official_brand(parse(name)):
                    found.add(name)
    return sorted(found)


def stream(keywords: list[str], writer):
    import certstream

    def cb(msg, _ctx):
        if msg.get("message_type") != "certificate_update":
            return
        for d in msg["data"]["leaf_cert"]["all_domains"]:
            d = d.lstrip("*.").lower()
            if any(k in d for k in keywords) and not official_brand(parse(d)):
                r = scan_many([d])[0]
                print(f"[{dt.datetime.now():%H:%M:%S}] {r['risk_score']:5} {r['verdict']:10} {d}", flush=True)
                writer.writerow([d, "ct_stream", "", r["risk_score"], r["verdict"],
                                 (r["impersonated_brand"] or {}).get("name", ""), r["reasons"][0]["en"] if r["reasons"] else ""])

    certstream.listen_for_events(cb, url="wss://certstream.calidog.io/")


def keywords_for(brand_ids):
    ks = set()
    for b in BRANDS:
        if not brand_ids or b["id"] in brand_ids:
            ks |= {k.replace("-", "") for k in b["keywords"] if len(k.replace("-", "")) >= 5}
    return sorted(ks)
