# SAWNN AI agents and orchestration

Code: `raqeeb/orchestrator.py` (queue, worker, workflows, scheduler) and `raqeeb/sawnn_agents.py` (the 16 agents).
API: `GET /api/v1/agents`, `POST /api/v1/agents/{id}/run`, `GET /api/v1/agents/activity`, `GET /api/v1/agents/workflows/{id}`.
Command: Investigations → *AI agents*.

## How the agents are connected

```
Protect report / Command request / scheduler job / discovery batch
        │ start_workflow(kind, input, origin, first_agent)
        ▼
  workflows ──< agent_tasks (queued → running → completed | failed)
        ▲            │ handler(input) → findings, evidence, confidence, sources, recommended_action, handoffs
        │            ▼
        └── enqueue(child task, parent_id = this task)   ← hand-off
```

- **Queue:** the `agent_tasks` table in the shared SQLite database. A worker thread (`start_worker`, started by the
  server) claims queued tasks in order; `drain()` runs the same loop synchronously for tests and scripts.
- **Hand-offs:** an agent's `handoffs` become new tasks in the same workflow with `parent_id` set, so the chain is
  stored, not drawn. Limits: 60 tasks per workflow, depth 5.
- **Record kept for every task:** agent name, task ID, workflow ID, parent, status, created/started/finished, execution
  time (ms), input and input references, findings, evidence, confidence, sources, errors, recommended action, hand-offs.
- **Failures** are caught, recorded with the error and a short traceback, and the workflow is marked *partial* or
  *failed*. They are never hidden (`test_failing_agent_is_recorded_not_hidden`).
- **Notifications:** agents call `_notify(event, data)`; the server forwards these to analysts over the WebSocket hub.

## The sixteen agents

| # | Agent (`id`) | Input | Does | Hands off to |
|---|---|---|---|---|
| 1 | Global Threat Hunter (`global_threat_hunter`) | batch of discovered indicators, or look-alike sweep | queues one URL Analysis per indicator; the sweep resolves brand look-alike domains in DNS | URL Analysis |
| 2 | Phishing Intelligence (`phishing_intelligence`) | URL | full quick scan through the Link Intelligence Engine; for discovered indicators records the verdict and opens a *Newly discovered* threat record if MALICIOUS/SUSPICIOUS, then notifies analysts | UAE Brand Impersonation, Sandbox Analysis (only with `SAWNN_DISCOVERY_SANDBOX=1`), Campaign Correlation |
| 3 | URL Analysis (`url_analysis`) | URL | PSL parsing, structural flags, model score | Phishing Intelligence |
| 4 | UAE Brand Impersonation (`uae_brand_impersonation`) | URL, or scheduled sweep | brand registry matching (host keyword, homoglyph, typosquat, path) | – |
| 5 | Sandbox Analysis (`sandbox_analysis`) | URL | deep scan: live page in the isolated browser, redirects, forms | Visual Impersonation |
| 6 | Visual Impersonation (`visual_impersonation`) | scan ID | reads the visual comparison for a deep scan | – |
| 7 | Message Intelligence (`message_intelligence`) | text | scam-script rules EN/AR, links, numbers | Sentiment, URL Analysis per link, Phone Intelligence per UAE number |
| 8 | Advertisement Intelligence (`advertisement_intelligence`) | text | advert rules | Sentiment |
| 9 | Phone Intelligence (`phone_intelligence`) | number | reports and verified threats for the number | – |
| 10 | QR Intelligence (`qr_intelligence`) | decoded payload | classifies the payload | URL Analysis for links |
| 11 | Campaign Correlation (`campaign_correlation`) | – | groups threats by shared domain, kit, report co-occurrence, text | Briefing (scheduled) |
| 12 | Seasonal Threat (`seasonal`) | – | seasonal outlook; predictions kept apart from confirmed incidents | – |
| 13 | Community Intelligence (`community`) | – | report-queue health | – |
| 14 | Sentiment & Social Engineering (`sentiment_social_engineering`) | text | tactics, phrases, sentiment, manipulation score (`raqeeb/sentiment.py`) | – |
| 15 | Intelligence Briefing (`briefing`) | period | daily/weekly briefing from recorded data | – |
| 16 | Protection Distribution (`protection_distribution`) | – | lists approved threats waiting for distribution; recommends only | – |

**Agents never** approve threats, publish protection, issue public alerts or block anything. Those steps stay with
authorised people in Command.

## Entry points

| Trigger | Workflow kind | First agent |
|---|---|---|
| Citizen report (`POST /api/citizen/report`, `/api/v1/reports`) | `citizen_report` | Message Intelligence |
| Scheduler `process_discoveries` | `discovery_batch` | Global Threat Hunter |
| Scheduler `uae_brand_discovery` | `uae_brand_sweep` | UAE Brand Impersonation |
| Scheduler `suspicious_domain_discovery` | `lookalike_sweep` | Global Threat Hunter (DNS) |
| Scheduler `campaign_correlation`, `seasonal_analysis`, `intelligence_briefing` | matching kinds | matching agent |
| Analyst *Run* in Command | `manual` | chosen agent |

## Sentiment and social-engineering analysis

`raqeeb/sentiment.py` detects 13 tactic groups in English and Arabic: urgency, artificial deadlines, fear, threats of
punishment, authority impersonation, account-suspension warnings, payment pressure, financial pressure, false rewards,
emotional manipulation, secrecy, requests for codes or passwords, manipulative reassurance. It returns the language,
overall sentiment, matched phrases, manipulation score, a pressure-plus-action flag, confidence and a bilingual
explanation. It is **supporting evidence only**: in `messages.check_message` it can add weight when the message also
has a link, brand or scam script, and on its own it can never lift a message above risk 30 (below SUSPICIOUS).
Tested: `test_social_engineering_analysis_en_ar_is_supporting_only`. API: `POST /api/v1/analysis/social-engineering`.

## Tests

`tests/test_sawnn.py`: `test_sixteen_agents_run_through_the_orchestrator_with_handoffs`,
`test_failing_agent_is_recorded_not_hidden`, `test_citizen_report_enters_the_agent_pipeline`,
`test_discovery_pipeline_creates_investigations_and_notifies`, `test_scheduler_runs_jobs_and_records_failures`.
