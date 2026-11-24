"""Twin view: line a scam domain up against the official one and mark every character that differs."""
import difflib
import unicodedata

from .urlparse import parse


def _label(domain: str) -> str:
    return domain.split(".")[0]


def char_flags(host_unicode: str) -> list[dict]:
    """Characters outside plain ASCII, with their Unicode names (e.g. CYRILLIC SMALL LETTER A)."""
    out = []
    for i, ch in enumerate(host_unicode):
        if ord(ch) > 127:
            out.append({"index": i, "char": ch, "name": unicodedata.name(ch, "UNKNOWN").title(),
                        "codepoint": f"U+{ord(ch):04X}"})
    return out


def twin(url: str, official_domains: list[str]) -> dict | None:
    """Pick the closest official domain and return aligned segments for both sides."""
    if not official_domains:
        return None
    p = parse(url)
    host = p.host_unicode
    best, best_ratio = None, -1.0
    for d in official_domains:
        r = difflib.SequenceMatcher(None, host, d).ratio()
        if r > best_ratio:
            best, best_ratio = d, r
    sm = difflib.SequenceMatcher(None, host, best, autojunk=False)
    scam, real = [], []
    for op, a0, a1, b0, b1 in sm.get_opcodes():
        if op == "equal":
            scam.append({"text": host[a0:a1], "type": "same"})
            real.append({"text": best[b0:b1], "type": "same"})
        elif op == "replace":
            scam.append({"text": host[a0:a1], "type": "changed"})
            real.append({"text": best[b0:b1], "type": "changed"})
        elif op == "insert":
            real.append({"text": best[b0:b1], "type": "missing"})
        elif op == "delete":
            scam.append({"text": host[a0:a1], "type": "added"})
    return {"scam_host": host, "scam_host_ascii": p.host, "official": best, "similarity": round(best_ratio, 3),
            "scam_segments": scam, "official_segments": real, "unicode_tricks": char_flags(host)}
