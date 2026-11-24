# SAWNN صون — UAE scam intelligence and citizen protection

ScamShield AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi. (Formerly RAQEEB; the Python package keeps the module name
`raqeeb` for import stability, everything users see is SAWNN.)

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

## Run it (macOS / Linux, Python 3.10+, 3.12 recommended)
```bash
cd sawnn                                   # the folder that contains requirements.txt
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt            # on a Mac also: brew install libomp tesseract tesseract-lang
SAWNN_DEMO=1 uvicorn server.app:app --host 0.0.0.0 --port 8000
```
Open **http://localhost:8000/**. Optional: `pip install playwright && python -m playwright install chromium` for deep
scans in a real browser. Phones on the same Wi-Fi: `http://<laptop-ip>:8000/app` (Command → *Connect phones* shows a QR).

| Demo account (demo mode only — never reuse) | Password | App |
|---|---|---|
| admin@sawnn.demo | SawnnDemo2026! | Command (Super Administrator) |
| analyst@sawnn.demo | AnalystDemo2026! | Command (Cybercrime Analyst) |
| citizen@sawnn.demo | CitizenDemo2026! | Protect |

Command → Operations → *Demo scenario* → *Run steps 1–5* seeds the winter-camping scenario. It also seeds a synthetic
redirect-chain sample (`SCAN-DEMO-REDIRECT1`) and two citizen alerts waiting in the workflow. All seeded data is marked
**Demo** and *Remove demo data* deletes it.

## Detection results (measured — see `docs/MODEL_REPORT.md`)
Domain-grouped held-out test split: 154,596 URLs, none of whose registered domains appear in training.

| | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| RAQEEB 2.1 hostname model | 96.8% | 52.8% | 0.683 | 1.85% |
| **SAWNN full-URL model (deployed)** | **99.7%** | **76.6%** | **0.866** | **0.25%** |

End-to-end verdicts on 2,500 phishing + 2,500 legitimate test URLs (feeds off):

| | Phishing marked SAFE | Legitimate wrongly flagged |
|---|---|---|
| RAQEEB 2.1 | 25.0% | 15.5% |
| SAWNN | **0.12%** | **2.3%** |

On an unseen OpenPhish snapshot the model catches 83.3%. This is **not** the 99.9% target. The report explains the errors
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
pytest -q        # 96 tests
```

## Configuration
Copy `.env.example` to `.env`. Every external service is optional and documented in
[`docs/API_GUIDE.md`](docs/API_GUIDE.md): what it does, where to get access, cost, env var, file, how to test, what happens
without it. Swagger UI: `/docs`.

## Documentation
- [`docs/STATUS.md`](docs/STATUS.md): every feature labelled IMPLEMENTED AND TESTED / NOT FULLY TESTED / PARTIAL / SIMULATED / NOT IMPLEMENTED / BLOCKED BY MISSING ACCESS, with the test commands.
- [`docs/MODEL_REPORT.md`](docs/MODEL_REPORT.md): root causes of the SAFE bug, dataset report, metrics, error analysis.
- [`docs/API_GUIDE.md`](docs/API_GUIDE.md): SAWNN API Integration & Configuration Guide.
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
