# SAWNN (صون) architecture

```
 SAWNN Protect (/app, PWA)            SAWNN Command (/command)            /signin prototype
        │  REST + WebSocket                    │  REST + WebSocket
        ▼                                      ▼
 ┌───────────────────────── Shared SAWNN backend (FastAPI, server/) ─────────────────────────┐
 │  /api/v1/scan · attachments · reports · notifications · agents · scheduler · sandbox ·    │
 │  models · intelligence · organizations          RBAC, rate limits, CSP, audit log         │
 └──────────────┬──────────────────────────┬───────────────────────────┬────────────────────┘
                ▼                          ▼                           ▼
   Link Intelligence Engine      AI Agent Orchestrator        Global Threat Discovery Engine
   raqeeb/link/*                 raqeeb/orchestrator.py       raqeeb/discovery.py
   validate → static → registry  queue (agent_tasks),         feeds → indicators → scheduler
   → signatures → model → DNS/   16 agents, hand-offs,        jobs → Global Threat Hunter
   TLS/RDAP → sandbox → redirects workflows, scheduler        batches
   → visual → risk aggregation
                └──────────────── one SQLite database (raqeeb/db.py, 6 migrations) ─────────────┘
```

**One pipeline, every entry point.** A link pasted in Protect, an image upload, a citizen report, an analyst's scan and a
feed discovery all go through the same Link Intelligence Engine; reports and discoveries also start agent workflows.

**Flow of intelligence.**
citizen report → agents (message, sentiment, URL, phishing) → threat record → analyst verifies → administrator approves →
signed protection package → every Protect device (Ed25519-verified) · discovery → agents → *Newly discovered* threat record →
same path · approved threat → citizen alert (draft → review → approve → publish) → Protect inbox.

**Rules no component can bypass:** citizen reports and feed discoveries never block anything; agents never approve,
block or publish; sandbox failure or missing evidence never yields SAFE; MALICIOUS needs strong independent evidence or
a model probability above the validated high-precision floor; delivery is only reported when a channel confirms it.

## Components and files

| Area | Files |
|---|---|
| Server, routes | `server/app.py`, `server/v2.py` (accounts, threats, citizens), `server/api_v1.py` (scan, health, registry), `server/api_sawnn.py` (attachments, reports, sandbox, models, alerts, agents, scheduler), `server/signin_demo.py`, `server/hub.py` (WebSocket) |
| Detection | `raqeeb/link/` (url_validator, static_analyzer, official_domains, signatures, ml, sandbox, redirects, visual, risk, pipeline, sandbox_config), `raqeeb/engine.py`, `raqeeb/model.py`, `raqeeb/features.py`, `raqeeb/brands.py` |
| Text | `raqeeb/messages.py`, `raqeeb/sentiment.py`, `raqeeb/assistant.py`, `raqeeb/translate.py` |
| Attachments | `raqeeb/attachments.py` |
| Agents | `raqeeb/orchestrator.py`, `raqeeb/sawnn_agents.py`, `raqeeb/agents.py` (shared helpers) |
| Discovery | `raqeeb/discovery.py`, `raqeeb/hunt.py` |
| Workflow and policy | `raqeeb/intel.py`, `raqeeb/community.py`, `raqeeb/protection.py`, `raqeeb/alerts.py`, `raqeeb/auth.py`, `raqeeb/security.py` |
| Data and models | `data/build_dataset.py`, `train_sawnn.py`, `tune_malicious_threshold.py`, `evaluate_sawnn.py`, `evaluate_precision.py`, `models/` |
| Front ends | `web/shared/` (tokens, fonts, logo, `lang.js`, `clip.js`), `web/app/`, `web/command/`, `web/signin/`, `web/index.html` |

## Data model (main tables)

users, sessions · threats, investigation_notes, corroborations · citizen_reports · scans (full report JSON incl. redirects,
sandbox, visual) · organizations · protection_versions · citizen_alerts, citizen_alert_versions, alert_deliveries,
alert_engagement, alert_subscriptions · attachments (hash + report) · indicators, discovery_runs · agent_tasks, workflows ·
scheduler_jobs, scheduler_runs · model_evals · findings · audit.

The Python package keeps the internal module name `raqeeb` so imports and the database survive the renames; every
name users see is SAWNN / صون.
