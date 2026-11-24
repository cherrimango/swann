"""URL validation and normalisation. Uses the offline Public Suffix List (tldextract), so
login.uaepass.example.com is recognised as belonging to example.com."""
import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from ..urlparse import CONFUSABLES, _EXTRACT, SHORTENERS

MAX_LEN = 4096
SUSPICIOUS_CHARS = set("@~^|\\{}<>`")
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|jpg|png|zip|txt)\.(exe|scr|js|bat|cmd|apk|html?|php|vbs)$", re.I)
SCRIPTS = (("LATIN", "latin"), ("CYRILLIC", "cyrillic"), ("GREEK", "greek"), ("ARABIC", "arabic"), ("ARMENIAN", "armenian"))


class InvalidURL(ValueError):
    pass


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    return next((s for key, s in SCRIPTS if name.startswith(key)), "other")


def validate(raw: str) -> dict:
    """Return the parsed URL with structural flags. Raises InvalidURL for input that is not a web URL."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidURL("Enter a URL")
    original = raw
    s = raw.strip().strip("'\"<>")
    if len(s) > MAX_LEN:
        raise InvalidURL("URL is too long to analyse")
    s = s.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
    if re.search(r"\s", s):
        s = re.sub(r"\s+", "", s)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "http://" + s
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError as e:
        raise InvalidURL(f"Malformed URL: {e}") from e
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURL(f"Only web links (http/https) can be analysed, not {scheme}:")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidURL("The URL has no host name")

    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host, re.I):  # dword / hex IPs like http://3232235777/
            is_ip = True
    try:  # IDNA: keep both the ASCII (punycode) and the Unicode form people see
        host_ascii = host.encode("idna").decode("ascii").lower() if not host.isascii() else host.lower()
    except UnicodeError as e:
        raise InvalidURL("The host name contains characters that are not valid in a domain") from e
    try:
        host_unicode = host_ascii.encode("ascii").decode("idna")
    except UnicodeError:
        host_unicode = host_ascii

    ext = _EXTRACT(host_ascii)
    registered = host_ascii if is_ip else ".".join(p for p in (ext.domain, ext.suffix) if p)
    path = parts.path or "/"
    query = parts.query
    netloc = host_ascii + (f":{port}" if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) else "")
    normalised = urlunsplit((scheme, netloc, re.sub(r"/{2,}", "/", path), query, ""))

    scripts = {x for x in (_script(c) for c in host_unicode) if x}
    homoglyph_skeleton = host_unicode.translate(CONFUSABLES)
    labels = [l for l in host_ascii.split(".") if l]
    flags = {
        "ip_address": is_ip,
        "embedded_credentials": bool(parts.username or parts.password),
        "at_symbol": "@" in (parts.netloc + path),
        "punycode": "xn--" in host_ascii,
        "internationalised_domain": not host_unicode.isascii(),
        "mixed_scripts": len(scripts - {"other"}) > 1,
        "homoglyph_characters": homoglyph_skeleton != host_unicode and not host_unicode.isascii(),
        "excessive_subdomains": len(ext.subdomain.split(".")) >= 4 if ext.subdomain else False,
        "excessive_hyphens": host_ascii.count("-") >= 4,
        "long_url": len(normalised) > 150,
        "long_host": len(host_ascii) > 60,
        "url_encoding": len(re.findall(r"%[0-9a-f]{2}", s, re.I)) >= 3,
        "suspicious_characters": any(c in SUSPICIOUS_CHARS for c in unquote(path + query)),
        "double_extension": bool(DOUBLE_EXT.search(path)),
        "non_standard_port": bool(port and port not in (80, 443)),
        "shortener": registered in SHORTENERS or host_ascii in SHORTENERS,
        "no_public_suffix": not is_ip and not ext.suffix,
        "embedded_url": bool(re.search(r"https?(://|%3a%2f%2f)", unquote(path + "?" + query), re.I)),
        "redirect_parameter": any(k.lower() in ("url", "redirect", "next", "goto", "return", "dest", "continue")
                                  and v.startswith(("http", "//")) for k, v in parse_qsl(query)),
    }
    return {
        "original_url": original, "normalised_url": normalised, "scheme": scheme, "hostname": host_ascii,
        "hostname_unicode": host_unicode, "registered_domain": registered, "subdomain": ext.subdomain,
        "domain_label": ext.domain, "tld": ext.suffix, "port": port, "path": path,
        "query_parameters": [k for k, _ in parse_qsl(query, keep_blank_values=True)], "fragment": parts.fragment,
        "url_length": len(normalised), "label_count": len(labels), "flags": flags,
        "homoglyph_skeleton": homoglyph_skeleton if flags["homoglyph_characters"] else None,
    }
