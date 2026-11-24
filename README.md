# RAQEEB رقيب: sees the scam before it reaches you

ScamShield AI Hackathon · 42 Abu Dhabi × Abu Dhabi Police

## The problem
UAE scams copy the services people trust most: UAE PASS, TAMM, police fines, Darb and Salik tolls, banks,
Emirates Post and Aramex, telecom rewards, attraction tickets. Fake sites go live and are shared by SMS, WhatsApp
and ads long before anyone reports them. Citizens who do spot one have nowhere quick to send it, and when police
confirm a scam, there is no fast way to protect everyone else.

## The solution
RAQEEB 2.0 is three connected systems:

| System | For | What it does |
|---|---|---|
| **RAQEEB Command** (`/`) | Police and analysts | Role-based console. It covers: a threat intelligence centre with a full record per threat (evidence, history, linked reports, notes); a verification workflow; global blocking with an approval policy; campaign correlation; a forecast; daily, weekly and monthly briefings; an emirate map; signed protection distribution with rollback; community abuse review; the audit log; user management. |
| **RAQEEB Protect** (`/app`) | Residents | A bilingual (Arabic/English, RTL) installable app with five tabs: **Home** (check a link, a message or a QR code; confirmed alerts; seasonal warnings), **Protect** (safe link preview, *Block for me*, brand verification registry, UAE PASS guard, family alerts), **Report** (11 report types, screenshot upload, impact questions, live status tracking), **Community** (Guardians leaderboards, public safety report, scam simulations, knowledge centre), **Profile** (points, level, badges, history explained, notifications, privacy settings). |
| **Intelligence engine** | Both | Ten deterministic agents with structured findings. Each finding records evidence, confidence, reasoning, source, timestamp and next action. A policy layer decides what agents may only recommend. Optional AI model; no paid API is required. |

### The loop
1. A citizen reports a scam.
2. AI analysis runs within seconds: the report type is detected; links, numbers and emails are extracted; the impersonated brand is named; the risk is explained in Arabic and English.
3. Duplicates are linked.
4. Other citizens corroborate it. This raises its priority but never blocks anything by itself.
5. An analyst verifies it, then a police approver confirms it and approves a global block.
6. A new protection version is signed with Ed25519 and pushed to every phone, the Android app and the DNS shield. Devices verify the signature and keep the rules for offline use.
7. Each block has an expiry, after which it is re-evaluated, and any version can be rolled back.
8. The reporting citizen is notified, and earns Guardian points only now that the report is verified. If the threat is later found to be a false positive, the points are reversed.

## What's real, and what isn't
- **221 real scam URLs targeting UAE brands**, mined from the public OpenPhish and Phishing.Database feeds (`data/uae_scam_urls.csv`).
  ⚠️ These are live phishing links. Treat the file as threat data.
- A URL model trained from scratch on 300,000 URLs, plus 34 UAE brand profiles with official domains.
- **Every number in RAQEEB Command and Protect is counted live from the database.** Nothing is hard-coded.
- `demo.py` fills an empty instance with **demo** data through the public API, the same way real users would:
  - Demo accounts end in `@raqeeb.demo`.
  - Their reports are built from the real mined URLs.
  - It is a rehearsal, not operational data.
- **Simulations are labelled as simulations.** Their links use the reserved `.example` domain. The UAE PASS guard on the web is a demonstration; the real guard is in the Android module.
- **Forecasts are always shown apart from confirmed threats**, in four separate classes: confirmed, emerging, predicted and historical.

## Detection results (honest numbers)
| Test | Precision | Recall | False-positive rate |
|---|---|---|---|
| ML model alone, held-out domains (61,896 URLs, split by registered domain, hostname only) | 98.2% | 68.7% | 1.3% |
| Full engine, UAE sanity set (60 real official/popular UAE sites + 53 synthetic impersonations), no threat feeds | 100% | 100% | 0% |

The UAE sanity set is small and its scam side is synthetic, so it checks the UAE rules rather than benchmarking the engine.

The hostname-only model is the floor:
- Brand rules, threat feeds and live checks raise recall.
- The live checks cover redirect unrolling, RDAP domain age, hosting, TLS age, page content and cloaking.

### How a link is judged
1. **Official allowlist.**
2. **Brand-copy rules:** names, typos, doubled letters, Unicode look-alikes, and paths on free-hosting sites.
3. **ML:** a character n-gram logistic regression stacked into LightGBM, with a threshold that keeps false positives at or under 1%.
4. **Threat feeds.**
5. **Optional live checks.**

Scores are calibrated so that 50 is the decision threshold.

## Policy and safety rules (enforced in code, not in the UI)
- **Who can block for everyone.** Only a Super Admin or Police Admin can approve a global block, and only for a threat in status `confirmed_malicious` (`raqeeb/protection.py`).
- **Citizens never block anyone else.** Corroboration needs at least 3 distinct, reputation-weighted citizens *and* an AI risk of at least 50, and it only moves a threat to `community_corroborated`.
- **Scope of a block.** Popular domains, free-hosting platforms and URL shorteners are blocked at **URL level**, or at host level for one `*.web.app` site, never the whole platform.
- **Expiry and rollback.** Every global block expires (30 days by default) and returns to review. Emergency rollback publishes a new version without the rolled-back rules.
- **Points.**
  - Paid only on transition to `analyst_verified` or `confirmed_malicious`.
  - A unique ledger key prevents double payment.
  - Reversed on `false_positive`.
  - Rejected and false-positive reports lower the reporter's reputation weight, which lowers their future corroboration weight.
  - Learning points are capped at 20 a day.
- **Privacy.**
  - Leaderboards are anonymous by default (`Guardian-NNNN`), can be switched off, and never expose emails or account IDs.
  - Locations are stored at emirate level only.
  - Family protection shares warnings that the user chooses to send. It never shares messages, browsing or location.
  - Citizens see their own reports only. Investigation detail stays in Command.

## Roles
| Role | Can |
|---|---|
| Super Administrator | Everything, including managing users |
| Police Administrator | Verify, approve and lift global blocks, roll back, review the community, read the audit log |
| Cybercrime Analyst | Investigate, verify threats, run hunts, collect evidence |
| Investigation Officer | Investigate, add case notes, collect and export evidence |
| Intelligence Analyst | Investigate, verify, run hunts, review the community |
| Read-only Supervisor | View the console and the audit log; no decisions, no evidence |
| Citizen | Use RAQEEB Protect only |

## Security
- **Accounts and sessions.** Passwords are hashed with scrypt; session tokens are random and stored only as SHA-256 hashes. Sessions last 12 hours for officials and 30 days for citizens. Every route checks the caller's role and permissions on the server.
- **Encryption.** Uploaded screenshots are validated (PNG/JPEG/WebP under 5 MB), re-encoded to strip metadata and trailing payloads, then **encrypted at rest** with Fernet.
- **Outbound requests.** Previews and evidence collection never reach internal addresses (loopback, private, link-local, metadata), and this is checked again on every redirect hop. Only ports 80, 443, 8080 and 8443 are allowed, and fetched pages are capped at 2 MB.
- **Rate limits.**
  - Sign-in is limited per address and per account.
  - Registration, reporting, corroboration, checks and uploads have their own limits.
- **Headers.** Responses carry a Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, and `no-store` on API responses.
- **Audit.** Every sign-in, decision, block, export and rollback is logged with its actor.
- **Untrusted content.** All submitted content is treated as untrusted: the interfaces insert it with `textContent` only, never as HTML.

Known limits:
- The SQLite database itself is not encrypted. Use SQLCipher or disk encryption in production.
- A DNS-rebinding race between the address check and the connection is possible in theory. Run the server behind an egress firewall in production.
- Push notifications go over the app's live connection. Firebase or APNs push is an adapter still to be added.

## Technical choices
Everything is our own code using permissively licensed open-source libraries, and every model is trained by us.

| Part | Built with |
|---|---|
| Engine, model, agents | Python, scikit-learn, LightGBM, tldextract, rapidfuzz |
| Server | FastAPI, WebSockets, SQLite (WAL, versioned migrations) |
| Security | cryptography (Ed25519 signing, Fernet), scrypt, Pillow |
| Command and Protect | Plain HTML/CSS/JS, no build step. Protect is an installable PWA with share target, QR scanning, offline cache and in-browser Ed25519 verification. |
| DNS shield | dnslib |
| Android | Kotlin: notification listener, call screening, call-state guard, signed offline rules (`android/`) |
| Optional AI | Any OpenAI-compatible endpoint, such as a local Ollama, through `RAQEEB_LLM_URL`. If it is unset, briefings are written by rules. |

## Run it
Python 3.10 or newer (3.12 recommended; on a Mac also run `brew install libomp`).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional: edit, then `set -a; source .env; set +a`

uvicorn server.app:app --host 0.0.0.0 --port 8000
```
- **RAQEEB Command:** http://localhost:8000/. On first start, one account per official role is created and the passwords are written to `data/first_run_credentials.txt`.
- **RAQEEB Protect:** http://&lt;laptop-ip&gt;:8000/app. Phones must be on the same Wi-Fi; *Connect phones* in Command shows a QR code.
- **Demo data (optional):** in a second terminal, run `python demo.py`.
- **DNS shield (optional):** `python dns_shield.py --port 53 --api http://localhost:8000`, then point a test phone's DNS at the laptop.

### Score a list of URLs (hidden test set)
```bash
python predict.py urls.csv -o predictions.csv        # CSV with a url column, or .txt with one URL per line
python predict.py --url "http://tamm-abudhabi-fines.top/pay"
```
Output columns: `url, label (1 = phishing), verdict, risk_score, impersonated_brand, reasons_en, reasons_ar`.

### Other tools
```bash
python evaluate.py data/uae_eval.csv --no-threat-intel   # precision / recall / FPR on any labelled CSV
python hunter.py permute --brand tamm                     # registered look-alikes of a brand
python data/download.py && python train.py                # refresh feeds and retrain (about 2 minutes)
pytest -q                                                 # 47 tests
```

## Tests
`pytest -q` runs 47 tests against a throwaway database:
- the 1.0 engine tests;
- 20 acceptance tests in `tests/test_v2.py`;
- a full-workflow test: report → AI analysis → corroboration → verification → confirmation → approval → signed distribution → device check → notification and reward.

| # | Acceptance criterion | Test |
|---|---|---|
| 1 | Official sign-in with roles; citizens register as citizens | `test_roles_and_registration` |
| 2 | RBAC: citizens can't open Command; a supervisor can't decide | `test_rbac` |
| 3 | Report type auto-detected; links and numbers extracted and explained | `test_report_auto_detects_type_and_indicators` |
| 4 | Report reference and private status tracking | `test_report_reference_and_tracking` |
| 5 | Duplicate reports detected | `test_duplicate_report` |
| 6 | Corroboration raises priority, never blocks | `test_corroboration_never_blocks` |
| 7 | Citizens can't block globally or roll back | `test_citizen_cannot_block_globally` |
| 8 | *Block for me* is personal only | `test_block_for_me_is_personal` |
| 9 | Global block needs approval permission and a confirmed threat | `test_global_block_policy` |
| 10 | URL-level blocking on shared platforms | `test_url_level_blocking_for_shared_platforms` |
| 11 | Signed, versioned packages; tampering detected | `test_signed_packages` |
| 12 | Emergency rollback | `test_rollback` |
| 13 | Expiry returns a block to review | `test_block_expiry` |
| 14 | Points only after verification, paid once | `test_points_only_after_verification` |
| 15 | Points reversed on false positive; reputation lowered | `test_points_reversed_on_false_positive` |
| 16 | Anonymous leaderboards, no emails, opt-out respected | `test_leaderboard_privacy` |
| 17 | Levels follow the thresholds | `test_levels` |
| 18 | Link and number from one message joined into one campaign | `test_campaign_correlation` |
| 19 | Forecast keeps confirmed, observed, predicted and historical apart | `test_forecast_separates_evidence_classes` |
| 20 | SSRF blocked, uploads validated, rate limits, audit, security headers | `test_security_controls` |

## Guardians
- **Points:** new website 20, phone 15, advertisement 25, SMS or email 15, useful screenshot 10, campaign link 30, independent confirmation 10, high-impact campaign 50, completed simulation 5. Override them with `RAQEEB_POINTS`.
- **Levels:** Observer 0, Scout 50, Defender 150, Sentinel 400, Guardian 900, Elite Guardian 2000, RAQEEB Champion 5000.
- **Badges:** First Verified Report, Phishing Hunter, Brand Protector, Campaign Detective, Community Guardian, Early Warning Contributor, Monthly Guardian, High Impact Discovery.

## API (main routes)
| Area | Routes |
|---|---|
| Accounts | `POST /api/auth/register`, `/login`, `/logout`; `GET /api/auth/me`; `/api/admin/users` |
| Threats | `GET /api/threats`, `GET /api/threats/{id}`, `POST /api/threats/{id}/status`, `/notes`, `/block`, `/unblock`, `/evidence`; `GET /api/threats/{id}/export` |
| Intelligence | `/api/command/overview`, `/api/intel/graph`, `/geography`, `/briefing`, `/forecast`, `/findings`, `/agents`, `/early-watch`, `/queue`, `/impact`; `/api/audit`; `/api/reports/queue`; `/api/community/abuse` |
| Protection | `GET /api/protection/latest` (signed), `/public-key`, `/versions`, `/check`; `POST /api/protection/rollback`; `GET /api/blocklist.txt` |
| Citizens | `POST /api/citizen/report` (multipart), `GET /api/citizen/reports[/{ref}]`, `/corroborate`, `/blocks`, `/profile`, `/notifications`, `/family` |
| Public | `/api/public/alerts`, `/leaderboard`, `/brands`, `/knowledge`, `/safety-report`, `/forecast`, `/meta`; `/api/preview`; `POST /api/learn/simulations/{id}` |
| 1.0 (kept) | `/api/scan`, `/api/check`, `/api/check-message`, `/api/feed`, `/api/campaigns`, `/api/hunt`, `/api/antibody`, `/api/evidence`. Investigation routes now need an official role, and `/api/antibody` goes through the 2.0 block policy. |
| Live | `WS /ws?token=…`: officials receive investigation events; citizens receive protection updates and their own report status changes. |

## Repository layout
```
raqeeb/        db (migrations), auth, security, intel (threat records), community, rewards, protection,
               agents, content, plus the 1.0 engine: urlparse, features, brands, model, engine, twin,
               messages, campaigns, scamcast, hunt, live, evidence, store
server/        app.py (pages, 1.0 routes, headers), v2.py (2.0 API), deps.py (auth, roles, rate limits), hub.py (live events)
web/command/   RAQEEB Command          web/app/   RAQEEB Protect (PWA)
android/       Kotlin module (see android/README.md)      docs/ios.md   iOS plan
data/ models/ tests/      train.py predict.py evaluate.py hunter.py dns_shield.py demo.py
```

## Limitations
- Most scam sites sit behind CDNs or offshore hosting, so the visible IP is rarely the scammer's. RAQEEB packages the evidence that requests to registrars, hosts, banks and telecoms need.
- A dead site can only be judged from its URL, and URL-only recall is the model's weakest point.
- **The Android module has not been compiled** (no Android SDK was available while it was written). iOS is a plan only (`docs/ios.md`).
- Screenshot OCR runs only if Tesseract is installed. Without it, the screenshot is stored as evidence and the analysis uses the pasted text.
- Brand domains marked `check` in `brands.json` must be verified with each entity before production.
- Dates for moon-sighted holidays in the forecast are approximate, and labelled as such.

## Credits
- **Data:** OpenPhish community feed; Phishing.Database (mitchellkrogza); top-1M domain list (zer0h); optional PhiUSIIL (Prasad & Chandra, CC BY 4.0) and PhreshPhish (OpenText).
- **UAE scam patterns:** public advisories by Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik, Emirates Post, ADCB and Emirates NBD.
