"""UAE brand impersonation detection: official-domain allowlist, brand keywords, typosquats, homoglyphs."""
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from rapidfuzz.distance import Levenshtein

from .urlparse import CONFUSABLES, FREE_HOSTING, LURE_WORDS, STRONG_LURES, ParsedURL, host_tokens, lure_tokens, under_any

_DATA = json.loads((Path(__file__).parent / "brands.json").read_text(encoding="utf-8"))
BRANDS = _DATA["brands"]
SCAM_TYPES = _DATA["scam_types"]
OFFICIAL = {d["domain"]: b for b in BRANDS for d in b["official_domains"]}


@dataclass
class BrandHit:
    brand_id: str
    brand_name: str
    brand_name_ar: str
    kind: str          # host_keyword | typosquat | homoglyph | path_keyword | weak_token
    matched: str
    keyword: str
    strength: float    # 0..1
    official: list
    scams: list


def official_brand(p: ParsedURL):
    d = under_any(p.host, OFFICIAL.keys())
    return OFFICIAL[d] if d else None


def _hit(b, kind, matched, kw, strength):
    return BrandHit(b["id"], b["name"], b["name_ar"], kind, matched, kw, strength,
                    [d["domain"] for d in b["official_domains"]], b["scams"])


def _strip_accents(s: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.combining(ch))


def collapse(s: str) -> str:
    """Collapse doubled letters: 'aquaaventure' -> 'aquaventure', 'ferrari' -> 'ferari'."""
    return re.sub(r"(.)\1+", r"\1", s)


def _label_variants(label: str) -> set[str]:
    base = label.lower()
    plain = _strip_accents(base)
    folded = base.translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")
    plain_folded = plain.translate(CONFUSABLES)
    return {base, folded, plain, plain_folded, base.replace("-", ""), folded.replace("-", ""), plain_folded.replace("-", "")}


_AFFIX_OK = STRONG_LURES | {"uae", "ae", "ad", "abudhabi", "dubai", "gov", "online", "app", "my",
                                "services", "e", "web", "pay", "sa", "uae1", "id", "x", "plus", "go"}


def _affix_match(label: str, k: str) -> bool:
    for tok in re.split(r"[-_]", label):
        if tok == k:
            return True
        rest_after, rest_before = tok[len(k):], tok[: -len(k)]
        if tok.startswith(k) and (rest_after in _AFFIX_OK or rest_after.isdigit()):
            return True
        if tok.endswith(k) and (rest_before in _AFFIX_OK or rest_before.isdigit()):
            return True
    return False


def detect(p: ParsedURL) -> list[BrandHit]:
    """Return brand impersonation hits for a URL that is NOT on an official domain."""
    if official_brand(p):
        return []
    hits: list[BrandHit] = []
    host_no_suffix = p.host_unicode[: -len(p.suffix) - 1] if p.suffix and p.host_unicode.endswith(p.suffix) else p.host_unicode
    labels = [l for l in host_no_suffix.split(".") if l]
    tokens = set(host_tokens(p))
    lures_present = bool(lure_tokens(p.url))
    path_q = (p.path + " " + p.query).lower()

    for b in BRANDS:
        best = None
        for kw in b["keywords"]:
            k = kw.replace("-", "")
            if len(k) <= 3:
                if kw in tokens and lures_present:
                    best = best or _hit(b, "weak_token", kw, kw, 0.45)
                continue
            for label in labels:
                for v in _label_variants(label):
                    if (len(k) >= 7 and (k in v or collapse(k) in collapse(v))) or (4 <= len(k) <= 6 and _affix_match(v, k)):
                        kind = "host_keyword" if v in (label.lower(), label.lower().replace("-", "")) and label.isascii() else "homoglyph"
                        cand = _hit(b, kind, label, kw, 0.95 if kind == "host_keyword" else 0.97)
                        if not best or cand.strength > best.strength:
                            best = cand
                for tok in re.split(r"[-_]", label.lower()):
                    if len(k) >= 5 and abs(len(tok) - len(k)) <= 1 and tok != k:
                        d = Levenshtein.distance(tok.translate(CONFUSABLES), k)
                        if d <= (1 if len(k) < 8 else 2):
                            cand = _hit(b, "typosquat", tok, kw, 0.9 if lures_present else 0.6)
                            if not best or cand.strength > best.strength:
                                best = cand
            if len(k) >= 4 and re.search(rf"(^|[^a-z0-9]){re.escape(k)}([^a-z0-9]|$)", path_q):
                on_hosting = under_any(p.host, FREE_HOSTING) is not None
                cand = _hit(b, "path_keyword", k, kw, 0.8 if (on_hosting or lures_present) else 0.5)
                if not best or cand.strength > best.strength:
                    best = cand
        if best:
            hits.append(best)
    hits.sort(key=lambda h: -h.strength)
    return hits
