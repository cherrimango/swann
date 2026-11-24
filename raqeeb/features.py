"""Handcrafted URL features. Every feature has a plain-language name used in explanations."""
import math
import re
from collections import Counter

from .urlparse import parse as parse_url
from .urlparse import FREE_HOSTING, LURE_WORDS, RISKY_TLDS, SHORTENERS, ParsedURL, under_any

FEATURE_NAMES = [
    "host_len", "host_dots", "host_hyphens", "host_digits", "host_entropy", "subdomain_depth",
    "longest_label", "is_ip", "is_punycode", "has_port", "tld_risky", "tld_len", "domain_len",
    "domain_digit_ratio", "domain_hyphens", "free_hosting", "shortener", "lure_words_host",
    "vowel_ratio", "consonant_run", "digit_letter_mix",
    # path / query features (zero in host mode)
    "url_len", "path_len", "path_depth", "query_len", "query_params", "lure_words_path", "has_at",
    "double_slash_path", "pct_encoded", "php_or_html", "has_https", "special_chars", "embedded_url",
    "path_entropy",
]

READABLE = {
    "host_len": "very long hostname", "host_dots": "many dots in hostname",
    "host_hyphens": "many hyphens in hostname", "host_digits": "digits in hostname",
    "host_entropy": "random-looking hostname", "subdomain_depth": "deep subdomain chain",
    "longest_label": "very long hostname label", "is_ip": "raw IP address instead of a domain",
    "is_punycode": "punycode / look-alike characters", "has_port": "non-standard port",
    "tld_risky": "high-abuse top-level domain", "tld_len": "unusual top-level domain",
    "domain_len": "unusual domain length", "domain_digit_ratio": "digits mixed into domain",
    "domain_hyphens": "hyphenated domain", "free_hosting": "free hosting / site-builder subdomain",
    "shortener": "URL shortener hides the destination", "lure_words_host": "lure words in hostname",
    "vowel_ratio": "unnatural letter pattern", "consonant_run": "random consonant string",
    "digit_letter_mix": "letters and digits mixed", "url_len": "very long URL",
    "path_len": "long path", "path_depth": "deep path", "query_len": "long query string",
    "query_params": "many query parameters", "lure_words_path": "lure words in path",
    "has_at": "'@' trick in URL", "double_slash_path": "redirect-style '//' in path",
    "pct_encoded": "heavy percent-encoding", "php_or_html": "script/static page path",
    "has_https": "uses HTTPS", "special_chars": "many special characters",
    "embedded_url": "another URL embedded inside", "path_entropy": "random-looking path",
    "lr_prob": "character pattern similar to known phishing URLs",
}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _count_lures(text: str) -> int:
    t = text.lower()
    return sum(1 for w in LURE_WORDS if w in t)


def _core_host(p: ParsedURL) -> str:
    return p.host[4:] if p.host.startswith("www.") else p.host


def extract(p: ParsedURL, include_path: bool = True) -> list[float]:
    host = _core_host(p)
    sub = p.subdomain[4:] if p.subdomain.startswith("www.") else ("" if p.subdomain == "www" else p.subdomain)
    labels = host.split(".") if host else []
    dom = p.domain or ""
    letters = re.sub(r"[^a-z]", "", dom)
    vowels = sum(ch in "aeiou" for ch in letters)
    runs = re.findall(r"[bcdfghjklmnpqrstvwxz]+", dom)
    f = [
        len(host), host.count("."), host.count("-"), sum(ch.isdigit() for ch in host), entropy(host),
        len([s for s in sub.split(".") if s]) if sub else 0,
        max((len(x) for x in labels), default=0), int(p.is_ip), int(p.is_punycode),
        int(p.port not in (None, 80, 443)), int(p.suffix.split(".")[-1] in RISKY_TLDS if p.suffix else 0),
        len(p.suffix), len(dom), (sum(ch.isdigit() for ch in dom) / len(dom)) if dom else 0.0,
        dom.count("-"), int(under_any(host, FREE_HOSTING) is not None),
        int(p.registered_domain in SHORTENERS or host in SHORTENERS), _count_lures(host),
        (vowels / len(letters)) if letters else 0.0, max((len(r) for r in runs), default=0),
        int(bool(re.search(r"[a-z]\d|\d[a-z]", dom))),
    ]
    if include_path:
        path, query = p.path, p.query
        f += [
            len(p.url), len(path), path.count("/"), len(query), query.count("&") + (1 if query else 0),
            _count_lures(path + "?" + query), int("@" in p.url.split("://", 1)[-1]),
            int("//" in path), p.url.count("%"), int(bool(re.search(r"\.(php|html?|aspx?)\b", path))),
            int(p.scheme == "https"), len(re.findall(r"[~!$*;,=+]", p.url)),
            int(bool(re.search(r"https?[:%]", path + query))), entropy(path),
        ]
    else:
        f += [0.0] * 14
    return f


def canonical(raw: str) -> str:
    """Form used by the full-URL model in training and inference: no scheme, no leading www., host lower-cased,
    repeated slashes collapsed, fragment dropped. Removing the scheme stops the model learning "HTTPS = safe"
    (an artefact of the attached url_dataset.csv, where every legitimate row is https://www.)."""
    p = parse_url((raw or "").strip().replace("&amp;", "&"))
    if not p.host:
        return (raw or "").strip()
    host = p.host.removeprefix("www.")
    if p.port not in (None, 80, 443):
        host += f":{p.port}"
    path = re.sub(r"/{2,}", "/", p.path or "")
    return (host + (path if path not in ("", "/") else "") + (("?" + p.query) if p.query else ""))[:2000]


def text_for_ngrams(p: ParsedURL, include_path: bool = True) -> str:
    host = _core_host(p)
    if include_path:
        return host + (p.path or "") + ("?" + p.query if p.query else "")
    return host
