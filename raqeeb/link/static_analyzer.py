"""Static URL analysis, plus domain (RDAP, DNS) and certificate features in deep mode.

Every block returns {"available": bool, ...}; failures are recorded as errors, never as evidence.
SSL validity is not proof of legitimacy, and a young domain is only one indicator.
"""
import datetime as dt
import hashlib
import math
import re
import socket
import ssl
from collections import Counter

from ..security import UnsafeTarget, check_url
from ..urlparse import LURE_WORDS, RISKY_TLDS

TIMEOUT = 5


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return round(-sum(n / len(s) * math.log2(n / len(s)) for n in c.values()), 3)


def url_features(v: dict) -> dict:
    url, host = v["normalised_url"], v["hostname"]
    path_q = v["path"] + ("?" + "&".join(v["query_parameters"]) if v["query_parameters"] else "")
    lures = sorted({w for w in LURE_WORDS if w in url.lower()})
    return {
        "available": True,
        "url_length": len(url), "domain_length": len(host), "subdomain_count": len(v["subdomain"].split(".")) if v["subdomain"] else 0,
        "dot_count": url.count("."), "hyphen_count": host.count("-"), "digit_count": sum(c.isdigit() for c in host),
        "special_char_count": len(re.findall(r"[^a-zA-Z0-9.\-/:]", url)), "ip_address": v["flags"]["ip_address"],
        "at_symbol": v["flags"]["at_symbol"], "query_parameter_count": len(v["query_parameters"]),
        "encoded_char_count": len(re.findall(r"%[0-9a-f]{2}", v["original_url"], re.I)), "suspicious_keywords": lures,
        "punycode": v["flags"]["punycode"], "shortener": v["flags"]["shortener"], "risky_tld": v["tld"].split(".")[-1] in RISKY_TLDS,
        "https": v["scheme"] == "https", "host_entropy": _entropy(v["domain_label"]), "path_depth": path_q.count("/"),
        "path_length": len(path_q), "non_standard_port": v["flags"]["non_standard_port"],
    }


def dns_features(host: str) -> dict:
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        try:
            ips = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
            return {"available": True, "method": "system resolver (install dnspython for MX/TXT/NS)", "a": ips}
        except OSError as e:
            return {"available": False, "error": f"DNS lookup failed: {e}"[:160]}
    res = dns.resolver.Resolver()
    res.lifetime = TIMEOUT
    out, errors = {"available": True, "method": "dnspython"}, {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            out[rtype.lower()] = sorted(r.to_text().strip('"')[:200] for r in res.resolve(host, rtype))
        except dns.resolver.NXDOMAIN:
            return {"available": True, "method": "dnspython", "nxdomain": True}
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            out[rtype.lower()] = []
        except dns.exception.DNSException as e:
            errors[rtype] = type(e).__name__
    if errors:
        out["errors"] = errors
    if all(not out.get(k) for k in ("a", "aaaa")) and errors:
        out["available"] = False
    return out


def certificate_features(host: str) -> dict:
    try:
        check_url(f"https://{host}/")
        ctx = ssl.create_default_context()
        validation_error = None
        try:
            with socket.create_connection((host, 443), timeout=TIMEOUT) as s, ctx.wrap_socket(s, server_hostname=host) as ss:
                c, der = ss.getpeercert(), ss.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as e:
            validation_error = e.verify_message or str(e)
            loose = ssl._create_unverified_context()  # noqa: S323 - only to read the invalid certificate's details
            with socket.create_connection((host, 443), timeout=TIMEOUT) as s, loose.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
            return {"available": True, "valid": False, "validation_error": validation_error,
                    "fingerprint_sha256": hashlib.sha256(der).hexdigest()}
        nb = dt.datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        na = dt.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        return {"available": True, "valid": True, "issuer": dict(x[0] for x in c.get("issuer", ())).get("organizationName"),
                "not_before": nb.isoformat(), "not_after": na.isoformat(), "age_days": (now - nb).days,
                "days_to_expiry": (na - now).days, "subject_alt_names": [v for k, v in c.get("subjectAltName", ())][:25],
                "fingerprint_sha256": hashlib.sha256(der).hexdigest()}
    except UnsafeTarget as e:
        return {"available": False, "error": f"not contacted: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:160]}


def domain_features(v: dict) -> dict:
    from ..live import rdap_domain
    out = {"rdap": {"available": False}, "dns": {"available": False}}
    if v["flags"]["ip_address"]:
        out["rdap"] = {"available": False, "error": "IP address: no domain registration"}
    else:
        r = rdap_domain(v["registered_domain"])
        if r.get("error"):
            out["rdap"] = {"available": False, "error": r["error"]}
        else:
            out["rdap"] = {"available": True, "registrar": r.get("registrar"), "registered": r.get("created"),
                           "age_days": r.get("age_days"), "nameservers": r.get("nameservers"), "abuse_contact": r.get("abuse_email")}
    try:
        check_url(v["normalised_url"])
        out["dns"] = dns_features(v["hostname"])
    except UnsafeTarget as e:
        out["dns"] = {"available": False, "error": f"not resolved: {e}"}
    out["certificate"] = certificate_features(v["hostname"]) if v["scheme"] == "https" else {"available": True, "https": False}
    return out
