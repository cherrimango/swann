# SAWNN Global Threat Discovery Engine

Code: `raqeeb/discovery.py` (sources, collection, storage, health), `raqeeb/orchestrator.py` (scheduler, processing),
`raqeeb/sawnn_agents.py` (Global Threat Hunter and the agents it hands off to). Command: Intelligence →
*Global Threat Discovery Engine*. API: `GET /api/v1/intelligence/sources/status`, `GET /api/v1/scheduler`,
`POST /api/v1/scheduler/{job}/run`, `POST /api/v1/intelligence/discovery/run`.

## The "SEO / search engine" from the earlier brief — what was actually there

Answers from the repository and from runtime tests (24 Nov 2026):

| Question | Before this update (RAQEEB 2.1 / MIRA) | Now (SAWNN) |
|---|---|---|
| 1. Does the engine exist? | No search/SEO engine. A manual Domain Hunter (`hunter.py`: look-alike permutations, crt.sh) and, in MIRA, a feed collector with an optional thread | Yes: the Global Threat Discovery Engine, run by the SAWNN scheduler |
| 2. Does it retrieve external information? | Only when an analyst ran the hunter, or with `MIRA_DISCOVERY_ENABLED=1` | Yes, on schedule, from the sources below (needs internet; failures recorded) |
| 3. Which sources? | OpenPhish, Phishing.Database (today), URLhaus (without the now-required key), PhishTank (key) | OpenPhish; Phishing.Database last hour + today; URLhaus (Auth-Key); PhishTank (app key); DNS for look-alikes |
| 4. Discovers suspicious URLs? | Collected them, did not analyse them | Every new URL is analysed by the agents |
| 5. Discovers new campaigns? | Only via manual correlation | Campaign Correlation runs every 30 min and after every suspicious discovery |
| 6. Monitors UAE brand impersonation? | Brand rules at scan time only | UAE Brand Impersonation sweep every 2 h over new indicators + look-alike DNS sweep |
| 7. Connected to the AI agents? | No | Yes: Global Threat Hunter → URL Analysis → Phishing Intelligence → Brand / Campaign / Sandbox |
| 8. Stores indicators? | Yes (`indicators`) | Yes, plus status, verdict, risk, registered domain, processing time, workflow and threat links |
| 9. Creates investigations? | No | Yes: MALICIOUS/SUSPICIOUS discoveries open a threat record with status *Newly discovered* and notify analysts |
| 10. Distributes verified intelligence to Protect? | Only through the analyst → approver path | Same, on purpose: discoveries are leads; distribution still needs analyst verification and official approval |

Verified by `test_discovery_pipeline_creates_investigations_and_notifies`, `test_scheduler_runs_jobs_and_records_failures`
and `test_discovery_records_new_duplicates_missing_keys_and_failures`.

## Sources

| Source | Key | Licence / terms | Default polling |
|---|---|---|---|
| OpenPhish community feed | none | non-commercial community feed | every 15 min (feed refreshes every few hours; duplicates are only counted) |
| Phishing.Database `phishing-links-NEW-last-hour.txt` | none | MIT | every 15 min |
| Phishing.Database `phishing-links-NEW-today.txt` | none | MIT | every 60 min |
| URLhaus recent URLs (`urlhaus-api.abuse.ch/v1/urls/recent/`) | `SAWNN_URLHAUS_AUTH_KEY` (free; mandatory since 30 Jun 2025) | abuse.ch terms | every 15 min |
| PhishTank online-valid | `SAWNN_PHISHTANK_APP_KEY` | PhishTank developer terms | every 60 min |
| DNS look-alike sweep | none | – | every 2 h (`SAWNN_HUNT_DNS=0` disables) |
| Google Web Risk, VirusTotal | keys | see API setup | at scan time only (deep scans), not polled |

Not connected: **Spamhaus** (DROP/DBL data needs a data-use agreement for commercial/government use), public
cybersecurity advisories and UAE advisories (no machine-readable feed was identified; patterns are encoded in the
message rules), Common Crawl, Tranco. These are documented gaps, not silent ones.

## Schedule (configurable)

| Job | Default | Env var |
|---|---|---|
| `feeds_high_priority` (OpenPhish, URLhaus, Phishing.Database hour) | 15 min | `SAWNN_SCHED_FEEDS_HIGH_PRIORITY_MIN` |
| `feeds_other` (Phishing.Database today, PhishTank) | 60 min | `SAWNN_SCHED_FEEDS_OTHER_MIN` |
| `process_discoveries` (Global Threat Hunter batch of 100) | 5 min | `SAWNN_SCHED_PROCESS_DISCOVERIES_MIN`, `SAWNN_DISCOVERY_BATCH` |
| `uae_brand_discovery` | 2 h | `SAWNN_SCHED_UAE_BRAND_DISCOVERY_MIN` |
| `suspicious_domain_discovery` | 2 h | `SAWNN_SCHED_SUSPICIOUS_DOMAIN_DISCOVERY_MIN` |
| `campaign_correlation` | 30 min | `SAWNN_SCHED_CAMPAIGN_CORRELATION_MIN` |
| `seasonal_analysis` | daily | `SAWNN_SCHED_SEASONAL_ANALYSIS_MIN` |
| `intelligence_briefing` | daily | `SAWNN_SCHED_INTELLIGENCE_BRIEFING_MIN` |
| `source_health` | 10 min | `SAWNN_SCHED_SOURCE_HEALTH_MIN` |
| `model_evaluation` | daily | `SAWNN_SCHED_MODEL_EVALUATION_MIN` |

The scheduler starts with the server (`SAWNN_SCHEDULER_ENABLED=0` stops it). On start-up every job is due, so the first
collection happens within about 30 seconds. Command shows *Scheduler running* only while the thread is alive in that
server process, and each job's real last status, next run, duration and last error.

## Workflow for each new URL

1. Collected with source and UTC timestamp (`indicators.first_seen`). 2. Normalised (scheme, case, invisible
characters) and deduplicated (`times_seen` counts repeats). 3. Registered domain extracted (offline Public Suffix List).
4. Queued by the Global Threat Hunter. 5. URL Analysis: structural flags and model score. 6. Phishing Intelligence:
full quick scan — existing SAWNN intelligence, published rules, bundled feed snapshot, brand registry, model, risk
aggregation. The indicator's own feed listing is excluded so the verdict is independent. 7. Optional isolated sandbox,
redirects, screenshot and visual comparison: only with `SAWNN_DISCOVERY_SANDBOX=1` on a dedicated sandbox host
(never visit live phishing from an ordinary workstation). 8. Campaign Correlation. 9. Verdict, risk and processing
time stored on the indicator. 10. MALICIOUS or SUSPICIOUS → threat record *Newly discovered* + analyst notification.
11. Analysts verify, an administrator approves, and only then is it distributed to Protect.

Discovered URLs are never declared malicious just because a feed listed them.
