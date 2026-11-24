# MIRA ميرا: See the threat. Stop the scam. Protect everyone.

ScamShield AI Hackathon · Abu Dhabi Police × 42 Abu Dhabi

## The problem
UAE scams copy the services people trust most: UAE PASS, TAMM, police fines, Darb and Salik tolls, banks, Emirates Post and Aramex, telecom rewards and event tickets. Fake sites go live and spread by SMS, WhatsApp and ads long before anyone reports them. A citizen who spots one has nowhere quick to send it. Even once police confirm a scam, there has been no fast, safe way to protect everyone else.

## The solution
One connected intelligence system with two applications:

- **MIRA COMMAND** (`/command`) is for authorised officials. It covers:
  - a live intelligence overview with an emirate map;
  - Domain Intelligence, a full investigation workspace for any URL;
  - scam campaigns, AI investigation, the citizen report queue and threat verification;
  - seasonal intelligence, Guardians and community review;
  - alerts and signed distribution, intelligence briefings, administration with the official brand registry, and audit logs.
- **MIRA PROTECT** (`/app`) is for citizens. It is a mobile-first PWA in English, Arabic and Urdu, with five tabs:
  - **Home**: check a link, Quick Alert for scam calls, *Ask MIRA*, "I've been scammed" guidance, verified alerts and seasonal warnings;
  - **Protect**: checkers for websites, payment links, QR codes, messages, phone numbers, adverts and apps; recent checks; Block for me; official website lookup; UAE PASS guard; family alerts;
  - **Report**: 11 report types, screenshots and status tracking;
  - **Community**: leaderboards, the public safety report, scam simulations and lessons;
  - **Profile**: points, level and badges.
- **The shared intelligence engine** has three parts:
  - the **Link Intelligence Engine** (validation, static analysis, official registry, signatures, domain/DNS/TLS, an isolated browser sandbox, visual comparison, ML, explainable risk aggregation);
  - ten agents with structured findings;
  - a policy layer that no agent or citizen can bypass.

**The cycle:** discover → analyse → correlate → analyst verifies → official approves → a signed protection update reaches every device → a citizen reports a related scam → it links to the campaign → the citizen earns Guardian points once it is verified.

## Run it
Python 3.10+ (3.12 recommended; on a Mac also run `brew install libomp`).
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
MIRA_DEMO=1 uvicorn server.app:app --host 0.0.0.0 --port 8000
```
- Open **http://localhost:8000/**. The entry screen lists the demo accounts.
- In COMMAND, *Demo scenario → Run steps 1–5* seeds the winter-camping scenario. The checklist then guides the live steps 6–11.
- To run without demo mode, drop `MIRA_DEMO=1`. The official accounts are then in `data/first_run_credentials.txt`.
- Phones on the same Wi-Fi can open `http://<laptop-ip>:8000/app`; *Connect phones* in COMMAND shows a QR code.

| Demo account (demo mode only, never reuse) | Password | App |
|---|---|---|
| admin@mira.demo | MiraDemo2026! | COMMAND (Super Administrator) |
| analyst@mira.demo | AnalystDemo2026! | COMMAND (Cybercrime Analyst) |
| citizen@mira.demo | CitizenDemo2026! | PROTECT |

**Optional extras**
- `pip install playwright && python -m playwright install chromium` enables deep scans in a real browser.
- `pip install pytesseract` plus the Tesseract binary (with English and Arabic) reads text from screenshots.
- `MIRA_LLM_URL` points to an OpenAI-compatible model, for example a local Ollama. It is used for briefings, assistant wording and translation.
- API keys in `.env` switch on Google Web Risk, VirusTotal and URLhaus. See `.env.example`.

### Score a list of URLs (hidden test set)
```bash
python predict.py urls.csv -o predictions.csv          # CSV with a url column, or .txt with one URL per line
python predict.py --url "http://tamm-abudhabi-fines.top/pay"
curl -s -X POST localhost:8000/api/v1/scan -H 'Content-Type: application/json' -d '{"url":"https://uaepass-verify.com/login"}'
```

### Tests and evaluation
```bash
pytest -q                   # 75 tests: engine, link engine, workflow, security, demo scenario, citizen tools
python compare_models.py    # Random Forest vs XGBoost vs the production model on the same domain-grouped split
python evaluate.py data/uae_eval.csv --no-threat-intel
```

## Detection results (measured, not estimated)
| Model on 61,896 held-out URLs (no registered domain appears in both training and test data) | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| **Production: char n-gram LR stacked into LightGBM** | **98.2%** | **68.7%** | **0.81** | **1.3%** |
| XGBoost (same 35 features) | 96.1% | 50.1% | 0.66 | 2.2% |
| Random Forest baseline | 97.8% | 59.3% | 0.74 | 1.5% |

These are hostname-only figures (`models/evaluation.json`): the legitimate data source lists domains, not full URLs. That makes them the floor; brand rules, threat feeds and deep-scan evidence raise recall. On the UAE sanity set (60 real official and popular UAE sites, 53 synthetic impersonations) the full engine scores 100% / 100% with no false positives. That set is small and its scam side is synthetic, so it checks the UAE rules rather than proving the system in general.

## Honesty rules this build follows
- Every number in COMMAND and PROTECT is counted from the database. Demo-seeded records carry a **Demo** label, and *Remove demo data* deletes them.
- Forecasts are shown apart from confirmed threats, in four classes: confirmed, emerging, predicted and historical.
- Model scores are labelled "not a calibrated probability". A stage that could not run is reported as unavailable, never as safe.
- "SAFE" means no significant indicators were found. It is not a guarantee.
- The assistant says plainly that it is not the police.
- A single citizen report never marks a number or site as malicious.

## Documentation
- [`docs/STATUS.md`](docs/STATUS.md): what is fully implemented, partial, demonstration-only, needs API keys, needs native permissions or needs future infrastructure, and what was tested.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): components, how they map to the requested structure, the scan report contract, the data model and the verification pipeline.
- [`docs/SOURCES.md`](docs/SOURCES.md): data and intelligence sources, with terms and limitations.
- [`android/README.md`](android/README.md) and [`docs/ios.md`](docs/ios.md): mobile modules and platform limits.

## Technical choices
| Part | Built with | Why |
|---|---|---|
| Engine, model, agents | Python, scikit-learn, LightGBM, tldextract (offline Public Suffix List), rapidfuzz | Fast, explainable, all trained by us |
| Sandbox and visual | Playwright + Chromium, BeautifulSoup fallback, Pillow/NumPy pHash, Tesseract OCR | Real page behaviour, without trusting the page |
| Server | FastAPI, WebSockets, SQLite (WAL, versioned migrations) | Runs anywhere with no setup; PostgreSQL is the production path |
| Security | cryptography (Ed25519, Fernet), scrypt, CSP and security headers, SSRF guard on every hop | Protection updates can't be forged; evidence is encrypted at rest |
| Interfaces | Plain HTML/CSS/JS with a shared token file; Inter, Roboto and Noto Sans Arabic | No build step, so the demo can't break on a toolchain |
| Mobile | PWA (share target, home-screen shortcuts, offline rules) plus a Kotlin Android module | Native features only where the OS allows them |

## Limitations
Full detail is in `docs/STATUS.md`. In short:
- The Android module has not been compiled, and iOS is a plan only.
- Visual comparison needs reference screenshots captured online (`data/capture_references.py`); logo detection and image embeddings are not implemented.
- The browser sandbox isolates at application level; container egress isolation is a deployment step (`infrastructure/`, not built here).
- SQLite is used instead of PostgreSQL and Redis.
- Translation and natural assistant wording need an optional model.
- The visible IP of a scam site is rarely the scammer's: MIRA packages evidence for registrars, hosts and banks, and never claims a location.

## Credits
- **Data:** OpenPhish community feed, Phishing.Database (mitchellkrogza), top-1M domain list.
- **UAE scam patterns:** public advisories by Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik, Emirates Post and UAE banks.
