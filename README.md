# SAWNN صون — UAE scam intelligence and citizen protection

ScamShield AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi. (Formerly RAQEEB, then MIRA; the Python package keeps the module
name `raqeeb` for import stability, everything users see is SAWNN / صون.)

## What it is
One shared threat-intelligence backend with two applications:

- **SAWNN Command** (`/command`), for authorised officials. Top-bar workspaces with contextual tabs:
  - **Operations:** live overview, intelligence reports, demo scenario.
  - **Intelligence:** live threat feed, the Global Threat Discovery Engine, campaigns, seasonal intelligence.
  - **Investigations:** link and domain analysis with a redirect-journey timeline, threat verification, citizen reports, 14 AI agents, and sandbox configuration and parameters.
  - **Response:** citizen alerts (draft → review → bilingual → approve → publish → delivery), blocking and distribution, community.
  - **System:** model evaluation, administration and the brand registry, audit logs.
- **SAWNN Protect** (`/app`), a mobile-first PWA for citizens.
  - Checking: links, **pictures and files** (screenshots, QR images, PDFs; camera, gallery, drag and drop), payment links, QR codes, messages, phone numbers, adverts and apps.
  - Reporting: report a scam, follow your own reports, and Block for me.
  - Official alerts: read approved SAWNN alerts and acknowledge them.
  - Community and Guardian points.
- **Demo sign-in prototype + security simulator** (`/signin`). It is a clearly labelled simulation of a national-ID style sign-in, plus an educational walk-through of fake-login tricks. It is not UAE PASS.

Languages: English and Arabic (full RTL), one global switch stored as `sawnn-lang`. Fonts: Roboto + Noto Kufi Arabic,
the pairing named by the UAE Design System, both SIL OFL, self-hosted. Logo: the supplied SAWNN mark (`web/shared/`).

Verdicts: **SAFE · SUSPICIOUS · MALICIOUS · INCONCLUSIVE**. Each comes with its risk score, confidence, analysis completeness
and analysis status. SAFE needs positive evidence; unknown or partly analysed sites are INCONCLUSIVE.

## Run it (macOS / Linux, Python 3.10+ — use 3.12; Apple's built-in 3.9 will not work)
```bash
cd ~/Desktop/sawnn                          # the folder that contains requirements.txt
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt             # on a Mac also: brew install libomp tesseract tesseract-lang
SAWNN_DEMO=1 uvicorn server.app:app --host 0.0.0.0 --port 8000
```
Open **http://localhost:8000/**. The scheduler (feed monitoring) and the agent orchestrator start with the server.
Demo accounts, the presenter walkthrough and what is simulated are in **[`docs/SAWNN_DEMO_GUIDE.md`](docs/SAWNN_DEMO_GUIDE.md)**
(not in the website).

## Precision target (measured — `docs/SAWNN_MODEL_EVALUATION.md`)
High-confidence MALICIOUS on 15,000 + 15,000 held-out URLs from unseen domains: **99.923% precision** (7,783 / 7,789),
Wilson 95% CI **99.83–99.97%**. The point estimate meets 99.9%; the confidence interval does not yet prove it.
Other high-risk URLs are reported as SUSPICIOUS (still a warning); only 0.21% of phishing test URLs came out SAFE.

## Detection results (measured — see `docs/SAWNN_MODEL_EVALUATION.md`)
Domain-grouped held-out test split: 154,596 URLs, none of whose registered domains appear in training.

| | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| RAQEEB 2.1 hostname model | 96.8% | 52.8% | 0.683 | 1.85% |
| **SAWNN full-URL model (deployed)** | **99.7%** | **76.6%** | **0.866** | **0.25%** |

End-to-end verdicts on 2,500 phishing + 2,500 legitimate test URLs (feeds off):

| | Phishing marked SAFE | Legitimate wrongly flagged |
|---|---|---|
| RAQEEB 2.1 | 25.5% | 15.0% |
| SAWNN | **0.12%** | **2.3%** |

On an unseen OpenPhish snapshot the model catches 83.3%. Overall recall is far from 99.9%; the 99.9% goal applies to the
precision of high-confidence MALICIOUS verdicts (above). The report explains the errors
and the next steps.

## Data and training
```bash
python data/download.py         # public feeds + top-1M list (needs internet)
python data/build_dataset.py    # attached url_dataset.csv + feeds → data/processed/sawnn-ds-<hash>.csv.gz + manifest
python train_sawnn.py            # trains, calibrates, evaluates, writes models/ and models/evaluation_sawnn.json
python evaluate_sawnn.py --old /path/to/raqeeb-2.1   # end-to-end verdict comparison
```
Place `url_dataset.csv` in `data/raw/` (not committed). Dataset `sawnn-ds-946b39760a` has 1,511,838 distinct URLs from
494,915 registered domains.

## Tests
```bash
pytest -q                                   # unit + API tests
python tests/e2e/clipboard_e2e.py --chrome /path/to/chrome   # real-browser clipboard test (server on :8011)
```

## Configuration
Copy `.env.example` to `.env`. Every external service is optional and documented in
[`docs/SAWNN_API_SETUP.md`](docs/SAWNN_API_SETUP.md): what it does, where to get access, cost, env var, file, how to test, what happens
without it. Swagger UI: `/docs`.

## Documentation
- [`docs/SAWNN_DEMO_GUIDE.md`](docs/SAWNN_DEMO_GUIDE.md), [`docs/SAWNN_ARCHITECTURE.md`](docs/SAWNN_ARCHITECTURE.md), [`docs/SAWNN_AI_AGENTS.md`](docs/SAWNN_AI_AGENTS.md), [`docs/SAWNN_THREAT_DISCOVERY.md`](docs/SAWNN_THREAT_DISCOVERY.md), [`docs/SAWNN_MODEL_EVALUATION.md`](docs/SAWNN_MODEL_EVALUATION.md), [`docs/SAWNN_API_SETUP.md`](docs/SAWNN_API_SETUP.md)
- [`docs/STATUS.md`](docs/STATUS.md): every feature labelled IMPLEMENTED AND TESTED / NOT FULLY TESTED / PARTIAL / SIMULATED / NOT IMPLEMENTED / BLOCKED BY MISSING ACCESS, with the test commands.
- [`docs/SAWNN_MODEL_EVALUATION.md`](docs/SAWNN_MODEL_EVALUATION.md): root causes of the SAFE bug, dataset report, metrics, error analysis.
- [`docs/SAWNN_API_SETUP.md`](docs/SAWNN_API_SETUP.md): SAWNN API Integration & Configuration Guide.
- [`docs/UAE_PASS_INTEGRATION.md`](docs/UAE_PASS_INTEGRATION.md): what the prototype simulates and the real path.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SOURCES.md`](docs/SOURCES.md), [`android/README.md`](android/README.md), [`docs/ios.md`](docs/ios.md).

## Honesty rules this build follows
- Every number on screen is counted from the database or from the evaluation files. Demo data is labelled.
- A missing API key or failed stage is reported as unavailable, never as clean, and a failed sandbox never gives SAFE.
- AI agents analyse and recommend. Only authorised people approve threats, block globally or publish citizen alerts.
- Citizen reports never trigger global blocks and are never used to retrain models automatically.
- Alert delivery is only reported when a channel confirms it. No push, e-mail or SMS adapters ship, so those channels say "not configured".

## Credits
Data: the attached `url_dataset.csv` (provenance not stated in the archive), OpenPhish community feed, Phishing.Database
(MIT), top-1M domain list. UAE scam patterns: public advisories (Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik,
Emirates Post, UAE banks). Fonts: Roboto and Noto Kufi Arabic (SIL OFL 1.1, licences in `web/shared/fonts/`).

## The problem and the solution
Scam links, fake messages and spoofed UAE brands reach residents faster than officials can verify and block them.
SAWNN gives citizens a mobile-first app to check links, files, QR codes, messages and numbers, and gives
authorised officials a command dashboard with live threat discovery, AI agents, reviewed citizen alerts and
global blocking. Both run on one shared threat-intelligence backend.

## Technical choices, tools, APIs and data
- **Backend:** Python, FastAPI, Uvicorn, SQLite.
- **Detection:** full-URL LightGBM + logistic regression model (scikit-learn), tldextract, rapidfuzz, DNS checks.
- **Files and images:** Pillow, OpenCV, pypdf, QR decoding; optional Tesseract OCR and Playwright sandbox.
- **Frontend:** vanilla JS PWA (English and Arabic, full RTL); Android client in Kotlin.
- **Data:** url_dataset.csv, OpenPhish, Phishing.Database, top-1M domain list.
- **Optional APIs (all work without keys):** Google Web Risk, VirusTotal, URLhaus, PhishTank, any OpenAI-compatible LLM.

## How to build and run (Windows PowerShell)

    cd sawnn
    py -m venv .venv
    .venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    $env:SAWNN_DEMO="1"
    python -m uvicorn server.app:app --host 0.0.0.0 --port 8000

Open http://localhost:8000/app (citizens), /command (officials), /signin (demo sign-in).
Demo accounts and walkthrough: docs/SAWNN_DEMO_GUIDE.md
