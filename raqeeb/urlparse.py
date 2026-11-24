"""URL normalisation and parsing shared by every SAWNN component."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, unquote

import tldextract

# Offline public-suffix snapshot: no network call at import time.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "t.ly", "ow.ly", "buff.ly", "rebrand.ly", "s.id", "tiny.cc", "lnkd.in", "qrco.de",
    "x.gd", "urlz.fr", "shorturl.asia", "short.gy", "tr.ee", "linktr.ee", "bit.do", "rebrandly.com",
    "surl.li", "u.to", "clck.ru", "gg.gg", "wa.link", "tinu.be", "1url.com",
}

FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "wix.com", "godaddysites.com", "vercel.app",
    "netlify.app", "github.io", "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "blogspot.com",
    "glitch.me", "herokuapp.com", "repl.co", "replit.app", "replit.dev", "webflow.io", "framer.app",
    "framer.website", "square.site", "mystrikingly.com", "carrd.co", "ngrok-free.app", "ngrok.io",
    "ngrok.app", "azurewebsites.net", "r2.dev", "ipfs.io", "dweb.link", "onrender.com", "surge.sh",
    "wordpress.com", "myshopify.com", "gitbook.io", "notion.site", "jimdosite.com", "webnode.page",
    "yolasite.com", "tiiny.site", "duckdns.org", "translate.goog", "firebasestorage.app",
    "appspot.com", "cloudfront.net", "amazonaws.com", "storage.googleapis.com", "sites.google.com",
    "glide.page", "my.canva.site", "canva.site", "webwave.dev", "site123.me", "wixstudio.com",
    "lovable.app", "bolt.host", "fly.dev", "railway.app", "deno.dev", "hpage.com", "ukit.me",
    "mobirisesite.com", "teachable.com", "typeform.com", "jotform.com", "forms.gle", "biz.id",
}

RISKY_TLDS = {
    "top", "xyz", "icu", "cyou", "sbs", "shop", "online", "site", "live", "click", "buzz", "rest",
    "cfd", "store", "vip", "monster", "lol", "support", "help", "quest", "bond", "win", "mom",
    "today", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "work", "fit", "link", "run", "best", "life",
    "zip", "mov", "xin", "loan", "country", "kim", "men", "date", "racing", "review",
}

LURE_WORDS = [
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "update",
    "account", "acct", "confirm", "unlock", "suspend", "suspended", "blocked", "reactivate", "kyc",
    "otp", "auth", "pay", "payment", "billing", "invoice", "refund", "fine", "fines", "violation",
    "toll", "parcel", "delivery", "shipment", "track", "redeem", "points", "reward", "bonus", "prize",
    "gift", "claim", "wallet", "bank", "card", "customs", "clearance", "visa", "renew", "emiratesid",
    "support", "service", "portal", "gov", "official", "alert", "notice", "overdue", "pending",
]

# Stronger, token-matched lure words used by the rule layer (LURE_WORDS above feed the ML features).
STRONG_LURES = {
    "login", "signin", "logon", "verify", "verification", "secure", "update", "account", "confirm", "unlock",
    "suspend", "suspended", "blocked", "reactivate", "kyc", "otp", "pay", "payment", "payments", "billing",
    "invoice", "refund", "fine", "fines", "violation", "violations", "toll", "tolls", "parcel", "delivery",
    "redeem", "reward", "rewards", "prize", "claim", "wallet", "card", "customs", "clearance", "overdue",
    "pending", "emiratesid", "bonus", "gift", "renew", "recharge", "topup", "auth", "password", "reset",
}


def lure_tokens(url: str) -> set[str]:
    toks = set(re.findall(r"[a-z]+", url.lower()))
    return {t for t in toks if t in STRONG_LURES}


CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ѡ": "w", "ı": "i",
})


@dataclass
class ParsedURL:
    raw: str
    url: str
    scheme: str
    host: str
    host_unicode: str
    port: int | None
    path: str
    query: str
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str
    is_ip: bool
    is_punycode: bool


def normalise(raw: str) -> str:
    u = (raw or "").strip().strip('"').strip("'")
    u = re.sub(r"\s+", "", u)
    u = u.replace("[.]", ".").replace("hxxp", "http")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    return u


def _to_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def parse(raw: str) -> ParsedURL:
    url = normalise(raw)
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        parts = urlsplit("http://invalid")
        host, port = "", None
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    ext = _EXTRACT(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return ParsedURL(
        raw=raw, url=url, scheme=parts.scheme.lower(), host=host, host_unicode=_to_unicode(host),
        port=port, path=unquote(parts.path or ""), query=unquote(parts.query or ""),
        subdomain=ext.subdomain, domain=ext.domain, suffix=ext.suffix,
        registered_domain=host if is_ip else registered, is_ip=is_ip,
        is_punycode="xn--" in host,
    )


def host_tokens(p: ParsedURL) -> list[str]:
    """Split hostname labels on dots, hyphens and underscores."""
    return [t for t in re.split(r"[.\-_]", p.host_unicode) if t]


def under_any(host: str, domains) -> str | None:
    """Return the matching domain if host equals it or is a subdomain of it."""
    for d in domains:
        if host == d or host.endswith("." + d):
            return d
    return None
