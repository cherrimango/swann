# MIRA API Integration & Configuration Guide

MIRA runs fully offline with no keys at all: the URL model, the brand registry, the bundled feed snapshot, the sandbox (when
the server has internet access) and OCR. Every external service below is **optional**. When one is not configured or fails,
MIRA lists it as "not checked" or "unavailable" in the scan report and carries on with the other layers. It never reads
a missing source as "clean".

Keys live only in the server environment (`.env`, see `.env.example`). Nothing is sent to the browser. `.env` is git-ignored.

Interactive API docs: start the server and open `http://localhost:8000/docs` (Swagger UI) or `/redoc`.

## 1. Summary

| Service | Needed for | Required? | Cost | Env var | Status in this build |
|---|---|---|---|---|---|
| OpenPhish community feed | discovery, signatures | optional | free, non-commercial | none | IMPLEMENTED; not tested live here (no outbound network) |
| Phishing.Database | training data, discovery, signatures | optional | free (MIT) | none | IMPLEMENTED; snapshot bundled in `models/` |
| URLhaus (abuse.ch) | deep-scan lookups, discovery | optional | free account | `MIRA_URLHAUS_AUTH_KEY` | BLOCKED BY MISSING API ACCESS (needs your key) |
| PhishTank | discovery | optional | free developer key | `MIRA_PHISHTANK_APP_KEY` | BLOCKED BY MISSING API ACCESS |
| Google Web Risk | deep-scan URL reputation | optional | free ≤100k lookups/month, then paid | `MIRA_GOOGLE_THREAT_API_KEY` | BLOCKED BY MISSING API ACCESS |
| VirusTotal | deep-scan multi-engine reputation | optional | free public API, non-commercial | `MIRA_VIRUSTOTAL_API_KEY` | BLOCKED BY MISSING API ACCESS |
| RDAP (rdap.org) | domain age, registrar | built in | free, rate-limited | none | IMPLEMENTED |
| DNS (dnspython, system resolver) | A/MX/NS/TXT, NXDOMAIN | built in | free | none | IMPLEMENTED |
| Certificate Transparency (crt.sh) | new look-alike domains (hunter) | built in | free, often slow | none | IMPLEMENTED (`hunter.py`) |
| Tranco / Common Crawl | larger training sets | optional | free, licence terms apply | none | NOT IMPLEMENTED as automatic adapters (files can be added to `data/raw/`) |
| Push / e-mail / SMS provider | citizen alert delivery | optional | provider pricing | `MIRA_PUSH_PROVIDER_KEY`, `MIRA_EMAIL_PROVIDER_KEY`, `MIRA_SMS_PROVIDER_KEY` | in-app delivery IMPLEMENTED AND TESTED; other channels report "not configured", no adapters shipped |
| UAE PASS | real national sign-in | production only | onboarding with UAE PASS | `MIRA_UAE_PASS_CLIENT_ID/SECRET/REDIRECT_URI` | SIMULATED FOR DEMONSTRATION (see `UAE_PASS_INTEGRATION.md`) |
| Tesseract OCR | screenshots, attachments | recommended | free (Apache 2.0) | none (install `tesseract` + `ara`, `eng`) | IMPLEMENTED AND TESTED |
| Playwright Chromium | sandbox | recommended | free | `MIRA_CHROMIUM` (optional path) | IMPLEMENTED; live visits not testable here |
| Local LLM (Ollama or any OpenAI-compatible) | rephrasing, translation | optional | free locally | `MIRA_LLM_URL`, `MIRA_LLM_MODEL`, `MIRA_LLM_KEY` | IMPLEMENTED BUT NOT FULLY TESTED |
| Model files | URL model | built in | – | `MIRA_MODEL_PATH` (default `models/`) | IMPLEMENTED AND TESTED |

## 2. Each service

### OpenPhish community feed
1. **What it does:** a text list of phishing URLs that are active right now.
2. **Why MIRA needs it:** fresh indicators for signature matching and for the Threat Discovery Engine.
3. **Access:** public GitHub feed `openphish/public_feed`. 4. **Registration:** none.
5. **Cost / limits:** free community feed for non-commercial use; it refreshes every few hours, so MIRA polls it at most hourly.
6–7. **Key / env var:** none. 8. **Backend file:** `raqeeb/discovery.py` (source `openphish`), `data/download.py`.
9. **Test:** Command → Intelligence → Threat discovery engine → *Collect now*; the source row should turn *healthy*.
10. **When unavailable:** the run is recorded as `failed` with the error; existing indicators and the bundled snapshot keep working.

### Phishing.Database
1. Community-maintained lists of phishing domains and links. 2. Training data and daily new links.
3. GitHub `Phishing-Database/Phishing.Database`. 4. None. 5. Free, MIT licence. 6–7. None.
8. `data/download.py`, `data/build_dataset.py`, `raqeeb/discovery.py` (`phishing_database_today`).
9. `python data/download.py` then `python data/build_dataset.py`; or *Collect now* in Command.
10. Same as above: recorded failure, nothing else changes.

### URLhaus (abuse.ch)
1. Database of URLs distributing malware, with a lookup API and recent-URL lists.
2. A second, malware-focused reputation source for deep scans, and new indicators for discovery.
3. Create a free account at `https://auth.abuse.ch/` and generate an Auth-Key. 4. **Yes.** abuse.ch made authentication
   mandatory on 30 June 2025, so without a key every request is refused.
5. Free; fair-use rate limits. 6. Auth-Key, sent as the `Auth-Key` HTTP header. 7. `MIRA_URLHAUS_AUTH_KEY` (old name `URLHAUS_AUTH_KEY` also works).
8. `raqeeb/link/signatures.py` (`_urlhaus`, deep scans), `raqeeb/discovery.py` (`urlhaus_recent`).
9. Set the key, run a deep scan of any URL: the report's *Threat intelligence* panel must list `urlhaus` under *Sources checked*.
10. Listed as *not checked (MIRA_URLHAUS_AUTH_KEY not set)* or, on error, under *Errors*. The verdict uses the other layers.

### PhishTank
1. Community-verified phishing URLs. 2. Discovery source. 3. Register an application at PhishTank's developer page.
4. Yes (application key). 5. Free with rate limits. 6–7. `MIRA_PHISHTANK_APP_KEY`.
8. `raqeeb/discovery.py` (`phishtank`, downloads `online-valid.csv`). 9. *Collect now*; health becomes *healthy*.
10. Health shows *needs MIRA_PHISHTANK_APP_KEY*; nothing is collected.

### Google Web Risk (Google's commercial Safe Browsing API)
1. Checks a URL against Google's lists of social-engineering and malware sites.
2. High-reliability reputation signal in deep scans. 3. Google Cloud console: enable *Web Risk API*, create an API key restricted to it.
4. Yes (Google Cloud project with billing). 5. Lookup API `uris.search` is free up to 100,000 calls a month, then $0.50 per 1,000.
6–7. `MIRA_GOOGLE_THREAT_API_KEY` (old name `GOOGLE_WEB_RISK_API_KEY`). 8. `raqeeb/link/signatures.py` (`_web_risk`).
9. Deep-scan a URL; `google_web_risk` appears under *Sources checked*. 10. *Not checked* / *Errors*; no effect on other layers.

### VirusTotal
1. URL reputation from many security vendors. 2. Optional extra opinion in deep scans.
3. Sign up at virustotal.com, copy the API key from your profile. 4. Yes. 5. The free public API allows 4 requests a minute and
500 a day and **must not be used in commercial products**; a government deployment needs a premium licence.
6–7. `MIRA_VIRUSTOTAL_API_KEY` (old `VIRUSTOTAL_API_KEY`). 8. `raqeeb/link/signatures.py` (`_virustotal`). Results are cached 30 minutes.
9. Deep scan; `virustotal` under *Sources checked*. 10. *Not checked* / *Errors*.

### RDAP, DNS and certificates
1. Domain registration (creation date, registrar, abuse contact), DNS records, and the site's TLS certificate.
2. Young domains, missing DNS and certificate problems are risk signals (never proof on their own). 3–7. No account or key.
8. `raqeeb/live.py` (`rdap_domain`), `raqeeb/link/static_analyzer.py` (`domain_features`). 9. Deep scan; *Registration and DNS* and *Certificate* panels fill in.
10. The panel says *unavailable* with the reason; analysis completeness drops; the verdict cannot become SAFE through a deep-scan path.

### Certificate Transparency (crt.sh)
1. Public log of issued certificates. 2. Finds newly certified look-alike domains for UAE brands. 8. `raqeeb/hunt.py`, `hunter.py`.
9. `python hunter.py --ct`. 10. The hunter logs the error and continues with other methods.

### Tranco and Common Crawl
Not wired as automatic adapters in this build (NOT IMPLEMENTED). To use them: download the files under their licences into
`data/raw/` and add a reader in `data/build_dataset.py`. Remember a popular-domain list is not a verified benign set.

### Push, e-mail and SMS providers
1. Deliver approved citizen alerts outside the app. 2. Reach citizens who are not in MIRA Protect at that moment.
3. Any provider your organisation approves (for example a push service, an SMTP relay, a licensed UAE SMS aggregator).
4–5. Provider-specific. 7. `MIRA_PUSH_PROVIDER_KEY`, `MIRA_EMAIL_PROVIDER_KEY`, `MIRA_SMS_PROVIDER_KEY`.
8. `raqeeb/alerts.py` (`publish`). **No provider adapter ships with MIRA**: with a key set, the delivery record says
*provider configured, adapter missing* and the recipient count stays 0. In-app delivery always works and is real.
9. Publish an alert with the channel ticked; check *Deliveries* in Command. 10. Delivery is recorded as `not_configured`; MIRA never claims a send.

### UAE PASS
See `docs/UAE_PASS_INTEGRATION.md`. Until official onboarding is complete the sign-in is a labelled simulation.

### OCR (Tesseract)
Install `tesseract` with the `eng` and `ara` language packs (macOS: `brew install tesseract tesseract-lang`).
Used by `raqeeb/attachments.py`, `raqeeb/link/visual.py`, `/api/public/check-ad`. Without it, attachment reports say
*Text in the image could not be read: Tesseract OCR not installed*, and QR decoding still works (OpenCV).

### Sandbox browser (Playwright Chromium)
`pip install playwright && playwright install chromium`, or point `MIRA_CHROMIUM` at Chrome. `MIRA_SANDBOX_ENABLED=false`
turns it off (scans then report the sandbox as disabled and cannot be SAFE through a deep scan). `MIRA_SANDBOX_TIMEOUT` sets the
navigation timeout in ms. A hardened container profile is in `infrastructure/sandbox/`.

### Local LLM
Any OpenAI-compatible chat endpoint (e.g. `ollama serve` → `MIRA_LLM_URL=http://localhost:11434`). Used only to rephrase
assistant answers and translate alert drafts (`raqeeb/assistant.py`, `raqeeb/translate.py`). URLs, numbers and codes are masked
before sending. Without it MIRA uses its own bilingual templates.

## 3. Endpoints

Authentication: `Authorization: Bearer <token>` from `POST /api/auth/login`. Roles: Super Administrator, Police Administrator,
Cybercrime Analyst, Intelligence Analyst, Investigation Officer, Read-only Supervisor, Citizen. Rate limits are per user or IP
(`MIRA_RATE_LIMITS`). Errors are JSON `{"detail": "..."}` with 400/401/403/404/409/410/413/422/429.

| Method & path | Who | Purpose |
|---|---|---|
| `POST /api/v1/scan` `{url, mode: quick|deep}` | anyone (deep: signed in) | Link Intelligence Engine; deep returns `{scan_id, status: running}` |
| `GET /api/v1/scan/{scan_id}` | owner or official | full report incl. `verdict`, `risk_score`, `assessment_confidence`, `analysis_completeness`, `analysis_status`, `redirects` |
| `GET /api/v1/scan/{scan_id}/screenshot` | `view_evidence` | sandbox screenshot |
| `POST /api/v1/reports` (multipart `type,text,emirate,impact,file`) | anyone | citizen report |
| `GET /api/v1/reports` · `GET /api/v1/reports/{ref}` | citizen: own · official: queue | report status |
| `POST /api/v1/attachments/analyze` (multipart `file`) | anyone | image / QR / PDF / text analysis |
| `GET /api/v1/intelligence/indicators` | `view_investigations` | verified threats + published rules |
| `GET /api/v1/intelligence/campaigns` | `view_investigations` | correlated campaigns |
| `GET /api/v1/intelligence/sources/status` | `view_investigations` | discovery source health + source registry |
| `POST /api/v1/intelligence/discovery/run` | `run_hunt` | collect from all feeds now |
| `GET /api/v1/sandbox/configuration` | `view_investigations` | sandbox parameters |
| `GET /api/v1/sandbox/{scan_id}` | `view_evidence` | sandbox evidence + collected parameters |
| `GET /api/v1/models/status` · `GET /api/v1/models/metrics` | anyone | model status and measured evaluation |
| `GET /api/v1/notifications` | officials: workflow · citizens: their alerts | citizen alerts |
| `POST /api/v1/notifications` · `PUT /api/v1/notifications/{id}` | `edit_investigation` | create / edit draft |
| `POST /api/v1/notifications/draft` | `edit_investigation` | AI-assisted bilingual draft (labelled) |
| `POST /api/v1/notifications/{id}/submit` | `edit_investigation` | send for review (needs EN + AR) |
| `POST /api/v1/notifications/{id}/review` `{approve, note}` | `verify_threat`, not the author | review |
| `POST /api/v1/notifications/{id}/approve` · `/publish` · `/withdraw` | `approve_threat` | approval and publication |
| `POST /api/v1/notifications/{id}/engage` `{action}` | signed-in citizen | opened / acknowledged / reported_related |
| `POST /api/v1/notifications/subscriptions` | signed-in citizen | opt-in categories |
| `GET /api/v1/agents` · `POST /api/v1/agents/{id}/run` | officials | 14 agents, structured results |
| `GET/POST /api/v1/organizations` | public / `manage_registry` | official-brand registry |
| `GET /api/v1/health` | anyone | component status |
| `POST /api/signin-demo/start` · `/{id}/respond` · `GET /{id}` | demo mode only | simulated sign-in prototype |

Example:

```bash
curl -s -X POST localhost:8000/api/v1/scan -H 'content-type: application/json' \
     -d '{"url":"https://login.uaepass.example.com/auth","mode":"quick"}' | jq '{verdict,risk_score,registered_domain,explanation}'
curl -s -F file=@qr.png localhost:8000/api/v1/attachments/analyze | jq '{verdict,qr,indicators}'
```
