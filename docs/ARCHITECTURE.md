# RAQEEB architecture

```
                 ┌──────────────── RAQEEB COMMAND (/command) ───────────────┐
                 │ officials: overview · live intelligence · domain intel │
                 │ campaigns · AI investigation · reports · verification  │
                 │ seasonal · Guardians · distribution · reports · admin  │
                 └───────────────▲───────────────────────────┬──────────────┘
                                 │ REST + WebSocket (role-scoped events)
┌────────── RAQEEB PROTECT (/app) ─────────┐         ┌────────┴───────── shared FastAPI server ──────────┐
│ citizens: check link/payment/QR/message/  │  REST   │ server/api_v1.py  Link Intelligence Engine API      │
│ phone/advert/app · report · Quick Alert   ├────────▶│ server/v2.py      threats, reports, protection,      │
│ assistant (EN/AR/UR) · Guardians · family │◀────────┤                   citizens, assistant, public       │
│ signed offline protection (Ed25519)       │  WS     │ server/deps.py    auth, roles, rate limits          │
└───────────────────────────────────────────┘         │ server/app.py     pages, headers, 1.0 routes         │
        Android shell (android/) ─────────────────────▶└────────┬──────────────────────────────────────────┘
                                                               │
        ┌──────────────────────── raqeeb/ (intelligence engine) ┴──────────────────────────────────────┐
        │ link/        url_validator → static_analyzer → official_domains → signatures → ml           │
        │              → (deep) domain intel · sandbox · visual → risk  ⇒ pipeline.analyse()            │
        │ agents.py    threat hunter · phishing · message · advert · phone · campaign correlation       │
        │              seasonal · community · briefing · distribution  (structured Findings)            │
        │ assistant.py language detection + tool calls + reviewed guidance (optional LLM rephrasing)   │
        │ community.py citizen reports, corroboration, review → rewards.py points/levels/badges        │
        │ protection.py signed versioned packages, URL/host/domain scope, expiry, rollback             │
        │ intel.py     threat records with provenance and history       db.py  SQLite + migrations     │
        └────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Mapping to the requested project structure
| Requested | In this repository |
|---|---|
| `frontend/command`, `frontend/protect` | `web/command`, `web/app`, plus `web/shared/tokens.css` (shared design system) and `web/index.html` (entry screen) |
| `backend/app/main.py`, `api/`, `auth/` | `server/app.py`, `server/api_v1.py`, `server/v2.py`, `server/deps.py`, `raqeeb/auth.py` |
| `detection/url_validator.py`, `static_analyzer.py`, `visual_analyzer.py`, `risk_engine.py` | `raqeeb/link/url_validator.py`, `static_analyzer.py`, `visual.py`, `risk.py` |
| `intelligence/official_domains.py`, `signature_detector.py`, `threat_feeds.py`, `source_registry.py` | `raqeeb/link/official_domains.py`, `signatures.py`, `source_registry.py`; feeds via `data/download.py` |
| `sandbox/browser_analyzer.py` | `raqeeb/link/sandbox.py` |
| `ml/train.py`, `predict.py` | `train.py`, `compare_models.py`, `raqeeb/model.py`, `raqeeb/link/ml.py`, `models/` |
| `agents/*.py` | `raqeeb/agents.py` (one module, ten agents), `raqeeb/assistant.py` |
| `database/` | `raqeeb/db.py` (versioned migrations) |
| `mobile/` | `android/`, `docs/ios.md`, PWA in `web/app` |
| `infrastructure/docker` | `infrastructure/Dockerfile`, `docker-compose.yml` |

The modules stay importable on their own: `from raqeeb.link import analyse` runs the full link engine without the web server.

## Scan report contract (`POST /api/v1/scan`)
```json
{
  "scan_id": "SCAN-20261124-1CAA64", "engine_version": "raqeeb-link-1.0", "mode": "quick | deep",
  "submitted_url": "...", "normalised_url": "...", "final_url": null, "registered_domain": "...",
  "verdict": "SAFE | SUSPICIOUS | MALICIOUS | INCONCLUSIVE", "risk_score": 0-100, "risk_level": "LOW | MODERATE | HIGH | CRITICAL",
  "assessment_confidence": "LOW | MEDIUM | HIGH", "analysis_completeness": 0-1,
  "detected_brand": "...", "official_domain_match": false, "official_domain_comparison": {...}, "twin_view": {...},
  "ml_result": {"available": true, "prediction": "...", "probability": 0.98, "probability_calibrated": false, "model_version": "...", "feature_contributions": [...]},
  "signature_result": {"known_threat": false, "sources_checked": [...], "sources_skipped": [...], "errors": {}, "matches": [...]},
  "static_analysis": {...}, "domain_intelligence": {...}, "website_analysis": {...}, "visual_analysis": {...},
  "evidence": [{"stage", "signal", "detail_en", "detail_ar", "direction": "risk|trust", "strength", "reliability"}],
  "strongest_indicators": [...], "explanation": {"en", "ar"}, "recommended_action": {"en", "ar"},
  "stages": {"validation": "complete", "sandbox": "not_run | unavailable | partial | complete", ...},
  "limitations": [...], "timestamp": "ISO-8601"
}
```

**How the verdict is reached**
- Risk levels: LOW is under 25, MODERATE 25–49, HIGH 50–74 and CRITICAL 75 and over (configurable with `RAQEEB_RISK_LEVELS`).
- MALICIOUS means CRITICAL, or a confirmed signature match.
- SUSPICIOUS means HIGH, or MODERATE with at least medium confidence.
- SAFE requires LOW plus available evidence.
- INCONCLUSIVE covers everything else, including a shortened link that was not followed.
- A stage that fails lowers completeness and confidence, never the score.

## Data model (main tables)
- `threats`: one row per indicator (`indicator_type` and `normalized` are unique together). Each row records:
  - category, brand, risk, severity, status and campaign;
  - an evidence observations list, an emirate count map and an append-only history (who, when, what);
  - block status, scope and expiry;
  - the `demo` flag and the source (provenance).
- `citizen_reports`: reference, type, raw text, extracted indicators, encrypted attachment id, emirate, impact, status, linked threat ids, AI analysis, duplicate link, details added later.
- Other tables: `corroborations`, `points` (ledger with a unique key per user, reason and threat), `badges`, `personal_blocks`, `families`, `notifications`, `learning`.
- `protection_versions`: rules, Ed25519 signature, publisher, notes, rollback flag.
- `scans` (link engine reports), `findings` (agent outputs), `organizations` (registry additions), `audit`, `users`, `sessions`, `metrics`.
- The 1.0 tables are kept: `feed`, `reports`, `blocklist`.

## Verification pipeline
discovery or citizen report → AI analysis → evidence collection → duplicate detection → campaign correlation → risk → **analyst verified** (`verify_threat`) → **officially approved** (`approve_threat`: Police or Super Admin) → global block (`approve_block`, approved threats only) → signed publication → citizen notification → expiry and re-evaluation (hourly job), revocation, rollback.

Agents and citizens cannot skip a step: each transition is checked on the server.
