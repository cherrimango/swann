"""Registry of the intelligence and data sources RAQEEB uses, with access terms and known limitations."""
import datetime as dt
import os

from ..engine import MODELS


def _mtime(name):
    f = MODELS / name
    return dt.datetime.fromtimestamp(f.stat().st_mtime, dt.timezone.utc).date().isoformat() if f.exists() else None


def sources() -> list[dict]:
    snap = _mtime("threat_hosts.txt.gz")
    model = _mtime("meta.json")
    return [
        {"name": "OpenPhish community feed", "access": "public HTTPS text feed (data/download.py)", "terms": "OpenPhish community feed terms; non-commercial",
         "collected": snap, "update_frequency": "on demand (feed refreshes every few hours)", "type": "phishing URLs", "coverage": "global",
         "used_for": ["model training", "signature matching"], "limitations": "small sample of currently active URLs; few UAE brands"},
        {"name": "Phishing.Database (mitchellkrogza)", "access": "public GitHub repository", "terms": "MIT licence",
         "collected": snap, "update_frequency": "on demand (repository updates daily)", "type": "phishing domains and URLs", "coverage": "global",
         "used_for": ["model training", "signature matching", "UAE scam URL mining"], "limitations": "contains some stale or parked entries"},
        {"name": "Top-1M domain list", "access": "public list (data/download.py)", "terms": "public research list",
         "collected": model, "update_frequency": "on demand", "type": "popular (legitimate) domains", "coverage": "global",
         "used_for": ["legitimate class for training", "popular-domain dampening"], "limitations": "popular does not mean safe; domains only, no paths"},
        {"name": "UAE scam URLs mined from the feeds", "access": "data/mine_uae_scams.py over the two phishing feeds", "terms": "derived from the feeds above",
         "collected": snap, "update_frequency": "on demand", "type": "real UAE-targeted phishing URLs (221)", "coverage": "UAE brands",
         "used_for": ["replay hunts", "kit campaign analysis", "demo reports"], "limitations": "selected by RAQEEB's brand detector, so not an independent test set"},
        {"name": "UAE official brand registry", "access": "raqeeb/brands.json plus administrator additions", "terms": "public websites of each organisation",
         "collected": "2026-11-24", "update_frequency": "manual, per organisation", "type": "official domains and brand keywords", "coverage": "UAE",
         "used_for": ["official-domain allowlist", "impersonation detection"], "limitations": "entries marked unverified must be confirmed with each entity"},
        {"name": "Public UAE fraud advisories", "access": "read manually (Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik, Emirates Post, banks)",
         "terms": "public advisories", "collected": "2026-11", "update_frequency": "manual", "type": "scam scripts and seasonal patterns",
         "coverage": "UAE", "used_for": ["message rules", "seasonal forecast"], "limitations": "patterns, not indicators; no automated ingestion yet"},
        {"name": "RDAP (rdap.org)", "access": "public RDAP over HTTPS, at scan time", "terms": "registry RDAP terms of use", "collected": "live",
         "update_frequency": "live", "type": "domain registration data", "coverage": "global",
         "used_for": ["domain age, registrar, abuse contact"], "limitations": "some ccTLDs return little data; rate limited"},
        {"name": "crt.sh Certificate Transparency", "access": "public JSON API, during hunts", "terms": "Sectigo crt.sh terms", "collected": "live",
         "update_frequency": "live", "type": "newly issued TLS certificates", "coverage": "global",
         "used_for": ["new look-alike domain discovery"], "limitations": "slow and often overloaded; certificates are not proof of a scam"},
        {"name": "Citizen reports (RAQEEB Protect)", "access": "in-app submissions", "terms": "user consent at submission", "collected": "live",
         "update_frequency": "live", "type": "untrusted reports with indicators and screenshots", "coverage": "UAE",
         "used_for": ["investigation leads", "corroboration"], "limitations": "untrusted until an analyst reviews them; never used to retrain models automatically"},
        {"name": "Google Web Risk", "access": "API (GOOGLE_WEB_RISK_API_KEY)", "terms": "Google Cloud terms", "collected": "live",
         "update_frequency": "live", "type": "URL reputation", "coverage": "global", "used_for": ["signature matching in deep scans"],
         "limitations": "optional", "configured": bool(os.environ.get("GOOGLE_WEB_RISK_API_KEY"))},
        {"name": "VirusTotal", "access": "API (VIRUSTOTAL_API_KEY)", "terms": "VirusTotal terms; public API is non-commercial", "collected": "live",
         "update_frequency": "live", "type": "multi-engine URL reputation", "coverage": "global", "used_for": ["signature matching in deep scans"],
         "limitations": "optional; strict rate limits", "configured": bool(os.environ.get("VIRUSTOTAL_API_KEY"))},
        {"name": "URLhaus (abuse.ch)", "access": "API (URLHAUS_AUTH_KEY)", "terms": "abuse.ch terms", "collected": "live",
         "update_frequency": "live", "type": "malware distribution URLs", "coverage": "global", "used_for": ["signature matching in deep scans"],
         "limitations": "optional; malware-focused rather than phishing", "configured": bool(os.environ.get("URLHAUS_AUTH_KEY"))},
    ]
