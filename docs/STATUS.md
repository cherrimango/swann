# RAQEEB: implementation status

Updated 24 November 2026. Every "tested" claim below is covered by `pytest -q` (75 tests, all passing) or was checked by hand in a browser, as stated.

## Fully implemented and tested
| Capability | Where | How it was tested |
|---|---|---|
| **Link Intelligence Engine**: validation (Public Suffix List, IDN, homoglyphs, IP forms, credentials, `@`, double extensions, redirect parameters), static features, official registry, signatures, ML, risk aggregation with separate score, confidence and completeness | `raqeeb/link/`, `POST /api/v1/scan` | `tests/test_link_engine.py` (Unicode, IDN, IP, malformed input, normalisation, verdict/level consistency, API contract) |
| **Browser sandbox**: real headless Chromium, every request re-checked against internal addresses, downloads refused, nothing submitted | `raqeeb/link/sandbox.py` | Test against a local fake login page; it finds the password field, the form sending data to another site and the brand text |
| **ML model**: char n-gram LR stacked into LightGBM, grouped by registered domain, TreeSHAP contributions | `train.py`, `raqeeb/link/ml.py` | Held-out domains: precision 98.2%, recall 68.7%, FPR 1.3% |
| **Model comparison** with Random Forest and XGBoost on the identical split | `compare_models.py`, `models/evaluation.json` | Production 0.81 F1, RF 0.74, XGBoost 0.66. The production model's test numbers match its training report exactly, which confirms the split is the same and nothing leaked |
| **Accounts and RBAC**: 6 official roles plus citizens; scrypt; hashed session tokens; permission checks on every route | `raqeeb/auth.py`, `server/deps.py` | `test_roles_and_registration`, `test_rbac` |
| **Verification workflow**: AI flagged → analyst verified → officially approved (separate permission) → global block | `server/v2.py`, `raqeeb/community.py` | `test_global_block_policy`, `test_full_workflow`, `test_demo.py` |
| **Citizen reporting**: 11 types, auto-detection, indicator extraction, duplicates, screenshots (validated, re-encoded, encrypted), impact questions, status tracking, adding details later | `raqeeb/community.py` | `test_v2.py` 3–5, `test_report_details_can_be_added_later` |
| **Community corroboration**: weighted by reputation; never blocks by itself | `community.corroborate` | `test_corroboration_never_blocks` |
| **Signed protection distribution**: Ed25519, versioned, URL-level rules for shared platforms, expiry, rollback; the browser verifies the signature itself (checked in Chrome) | `raqeeb/protection.py`, Protect app | `test_signed_packages`, `test_rollback`, `test_block_expiry`, `test_url_level_blocking_for_shared_platforms` |
| **Guardians**: points only after verification, never twice, reversed on false positives, anonymous leaderboards, levels and badges | `raqeeb/rewards.py` | `test_v2.py` 14–17 |
| **Campaign correlation**: shared domain, phishing kit, co-occurrence in one report, near-identical text | `agents.correlate` | `test_campaign_correlation`, demo test |
| **Seasonal intelligence**: confirmed, emerging, predicted and historical kept apart; counts real versus demo signals | `agents.seasonal_agent` | `test_forecast_separates_evidence_classes` |
| **Assistant** in English, Arabic and Urdu: detects the language, calls the link engine, phone and message tools, labels live checks versus general guidance | `raqeeb/assistant.py` | `test_assistant_uses_tools_and_answers_in_the_same_language` |
| **Message intelligence** in English, Arabic, Urdu and Roman Urdu | `raqeeb/messages.py` | `test_urdu_scam_message_is_detected` and 1.0 tests |
| **Phone and advert checkers**: one report never condemns a number | `server/v2.py` | `test_phone_checker_never_condemns_on_reports_alone`, `test_advert_checker` |
| **Security**: SSRF checks on every redirect hop, upload validation, rate limits (per address and per account for sign-in), CSP and other headers, audit log | `raqeeb/security.py`, `server/app.py` | `test_security_controls` |
| **Demo mode**: spec demo accounts plus the seeded winter-camping scenario through all 11 steps, then removable | `raqeeb/demo_scenario.py` | `test_winter_camping_scenario_end_to_end` |
| **Interfaces**: entry screen; COMMAND (13 sections plus demo); PROTECT (5 tabs, 7 checkers, assistant, Quick Alert, emergency guidance, EN/AR/UR with right-to-left layout) | `web/` | Checked by hand in headless Chrome at desktop and mobile sizes, with no console errors and no server errors |

## Partially implemented
| Capability | What works | What doesn't yet |
|---|---|---|
| **Visual impersonation** | pHash, layout and colour similarity against reference screenshots; OCR (English + Arabic) when Tesseract is installed; brand text on the page | No reference screenshots ship with the repo (`data/capture_references.py` needs internet). Logo detection and CLIP-style embeddings are not implemented. Without references the stage reports itself unavailable |
| **Domain intelligence** | RDAP, DNS (A, AAAA, MX, TXT, NS with dnspython), certificate details including SANs and fingerprint | Needs internet. Passive DNS is not integrated (it needs a licence) |
| **Domain Hunter** | Look-alike permutations that resolve, crt.sh certificates, seasonal watchlists, replay of real feed URLs | Not scheduled continuously; hunts run when an analyst starts them |
| **Screenshot OCR in reports** | Runs if `pytesseract` and the Tesseract binary are installed | Without them the screenshot is stored as evidence but not read |
| **Translation service** | URLs, numbers, amounts, codes and dates are masked and restored exactly (tested) | Needs an OpenAI-compatible model (`RAQEEB_LLM_URL`); without one it says it is unavailable |
| **Assistant wording** | Reviewed guidance plus live tool results, no model needed | Natural rephrasing only with `RAQEEB_LLM_URL` |
| **Database** | SQLite with versioned migrations and WAL; one connection per thread | Not PostgreSQL or Redis. Chosen so the demo runs with no setup; the schema is plain SQL and can be ported |
| **Interactive UAE map** | Clickable emirate-level breakdown (reports, threats, categories, campaigns) | A schematic layout, not a geographic map |

## Demonstration-only
- The **seeded winter-camping scenario**: step 1 is a simulated discovery. Its domains, phone number and messages are invented and marked as demo data. Steps 2–11 run the real engine and workflow.
- The **demo accounts** (`*@raqeeb.demo`) exist only with `RAQEEB_DEMO=1`.
- The **web UAE PASS guard** is a simulation. The real guard is the Android notification-listener code.
- **Scam simulations** in the Knowledge Centre use the reserved `.example` domain.

## Needs external API credentials (adapters written, off by default)
- Google Web Risk (`GOOGLE_WEB_RISK_API_KEY`), VirusTotal (`VIRUSTOTAL_API_KEY`) and URLhaus (`URLHAUS_AUTH_KEY`): deep-scan signature checks. Without a key they are listed as "not checked", never as clean.
- An optional LLM (`RAQEEB_LLM_URL`) for briefings, assistant rephrasing and translation.

## Needs native mobile permissions
- Android (`android/`, **written but not compiled**, because no Android SDK was available):
  - notification reading for SMS and WhatsApp scanning;
  - call-state reading for the UAE PASS guard;
  - call screening, which rejects confirmed scam numbers offline;
  - the Quick Settings tile for Quick Alert;
  - signed offline rules.
- iOS is a plan only (`docs/ios.md`): Message Filter, Call Directory and Share extensions.
- Power-button shortcuts are not used, because they are reserved for emergency functions on many phones. Quick Alert is reached through the in-app button, PWA home-screen shortcuts and the Android tile.

## Needs future infrastructure
- A Docker sandbox with network-level egress controls and CPU/memory limits. `infrastructure/Dockerfile` and `docker-compose.yml` are written but **not built** here, because no Docker daemon was available.
- Firebase or APNs push. Notifications currently travel over the live WebSocket and the browser Notification API.
- PostgreSQL/Redis, SQLCipher or disk encryption, and passive DNS feeds.
- A DNS-rebinding fix at the network layer: application checks run before each connection, but a race remains possible.
- An appeal workflow for citizens. False positives, revocation and rollback exist on the official side.
