# Data and intelligence sources

Generated from `raqeeb/link/source_registry.py` (also served live at `GET /api/v1/intelligence/sources`).
Real threat data, training data and demonstration data are kept apart: the model trains only on the public feeds and the top-1M list; citizen reports are never used to retrain automatically; demo records are flagged `demo = 1` and come from `raqeeb/demo_scenario.py`.

| Source | Access | Terms | Collected | Type | Coverage | Used for | Limitations |
|---|---|---|---|---|---|---|---|
| OpenPhish community feed | public HTTPS text feed (data/download.py) | OpenPhish community feed terms; non-commercial | 2026-11-24 | phishing URLs | global | model training, signature matching | small sample of currently active URLs; few UAE brands |
| Phishing.Database (mitchellkrogza) | public GitHub repository | MIT licence | 2026-11-24 | phishing domains and URLs | global | model training, signature matching, UAE scam URL mining | contains some stale or parked entries |
| Top-1M domain list | public list (data/download.py) | public research list | 2026-11-24 | popular (legitimate) domains | global | legitimate class for training, popular-domain dampening | popular does not mean safe; domains only, no paths |
| UAE scam URLs mined from the feeds | data/mine_uae_scams.py over the two phishing feeds | derived from the feeds above | 2026-11-24 | real UAE-targeted phishing URLs (221) | UAE brands | replay hunts, kit campaign analysis, demo reports | selected by MIRA's brand detector, so not an independent test set |
| UAE official brand registry | raqeeb/brands.json plus administrator additions | public websites of each organisation | 2026-11-24 | official domains and brand keywords | UAE | official-domain allowlist, impersonation detection | entries marked unverified must be confirmed with each entity |
| Public UAE fraud advisories | read manually (Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik, Emirates Post, banks) | public advisories | 2026-11 | scam scripts and seasonal patterns | UAE | message rules, seasonal forecast | patterns, not indicators; no automated ingestion yet |
| RDAP (rdap.org) | public RDAP over HTTPS, at scan time | registry RDAP terms of use | live | domain registration data | global | domain age, registrar, abuse contact | some ccTLDs return little data; rate limited |
| crt.sh Certificate Transparency | public JSON API, during hunts | Sectigo crt.sh terms | live | newly issued TLS certificates | global | new look-alike domain discovery | slow and often overloaded; certificates are not proof of a scam |
| Citizen reports (MIRA Protect) | in-app submissions | user consent at submission | live | untrusted reports with indicators and screenshots | UAE | investigation leads, corroboration | untrusted until an analyst reviews them; never used to retrain models automatically |
| Google Web Risk | API (GOOGLE_WEB_RISK_API_KEY) | Google Cloud terms | live | URL reputation | global | signature matching in deep scans | optional |
| VirusTotal | API (VIRUSTOTAL_API_KEY) | VirusTotal terms; public API is non-commercial | live | multi-engine URL reputation | global | signature matching in deep scans | optional; strict rate limits |
| URLhaus (abuse.ch) | API (URLHAUS_AUTH_KEY) | abuse.ch terms | live | malware distribution URLs | global | signature matching in deep scans | optional; malware-focused rather than phishing |
