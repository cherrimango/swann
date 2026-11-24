# RAQEEB رقيب — sees the scam before it reaches you

ScamShield AI Hackathon · 42 Abu Dhabi × Abu Dhabi Police

## The problem
UAE scams copy the services people trust most: UAE PASS, TAMM, police fines, Darb and Salik tolls, banks,
Emirates Post and Aramex, telecom rewards, attraction tickets. Fake sites go live and are shared by SMS, WhatsApp
and ads long before anyone reports them, and by the time a victim reports, the money has moved.

## The solution
RAQEEB is one system with two sides and one loop:

| Side | What it does |
|---|---|
| **Hunt** (police) | Finds fake UAE sites as they appear: look-alike domains, new TLS certificates, and a **ScamCast** watchlist of the fake names scammers register before each UAE season (Global Village, Eid Al Etihad, salary week, summer travel). |
| **Detect & trace** (police) | Scores every link with an explainable risk score and reasons in **Arabic and English**, names the UAE brand being copied, shows a **twin view** of the fake domain against the real one (down to a single Cyrillic letter), and groups scam sites into **campaigns by the phishing kit they share** (“Scam DNA”). One click builds a takedown-ready **evidence pack**. |
| **Shield** (residents) | A bilingual phone app: check any link, whole message or **QR code**; get police alerts instantly; a **UAE PASS guard** that stops an approval during a call; one-tap report to Aman. A **DNS shield** blocks scam domains on any phone pointed at it. |
| **The loop** | An officer’s “Block on every phone” pushes the domain to every connected phone and the DNS shield within seconds; resident reports flow back into the police feed. |

## What’s real in this repo
- **221 real scam URLs targeting UAE brands**, mined from the public OpenPhish and Phishing.Database feeds
  (`data/uae_scam_urls.csv`): Aramex, Emirates Post, e&, Emirates NBD, Mashreq, ADCB, Darb, ADIB, Salik.
  ⚠️ These are live phishing links: treat the file as threat data and don’t open them in a normal browser.
- **13 kit campaigns** found in that data, e.g. one Aramex kit (`/clients/cc.php`) reused on 17 domains, and one
  kit attacking both Emirates NBD and Mashreq (`/{hex}/card.php?id&v`).
- A model trained from scratch on 300,000 URLs (OpenPhish + Phishing.Database vs the top-1M domain list).

## Results (honest numbers)
| Test | Precision | Recall | False-positive rate |
|---|---|---|---|
| ML model alone, held-out domains (61,896 URLs, split by registered domain, hostname only) | 98.2% | 68.7% | 1.3% |
| Full engine, UAE sanity set (60 real official/popular UAE sites + 53 synthetic impersonations), no threat feeds | 100% | 100% | 0% |

The UAE sanity set is small and its scam side is synthetic, so treat it as a check of the UAE rules, not a
benchmark. The 221 mined URLs are all caught too, but they were selected by the same brand detector, so that
is not an independent test either. The hostname-only model is the floor: brand rules, threat feeds and live
checks raise recall, and training on full-URL datasets (`--mode url`) adds path signals.

## How detection works
1. **Official allowlist first**: real UAE PASS, TAMM, ICP, bank and attraction domains are never flagged
   (`raqeeb/brands.json`, 34 UAE brand profiles; entries marked `check` should be confirmed before go-live).
2. **Brand-copy rules**: brand names, typos, doubled letters and look-alike Unicode letters on domains the brand
   doesn’t own; brand names inside paths on free-hosting sites.
3. **ML model**: character n-gram logistic regression stacked into LightGBM over 35 URL features. The threshold
   is set on a validation split to keep false positives at or under 1%. Every flag lists its top feature
   contributions as reasons.
4. **Threat feeds**: exact match against hosts and URLs already reported publicly.
5. **Live checks** (`--live`): redirect unrolling (including client-side redirects), domain age (RDAP),
   hosting network, TLS certificate age, page content (card, OTP, Emirates ID, password fields; urgency),
   forms posting to another domain, and **cloaking** (bot vs phone content).

Scores are calibrated so 50 is the decision threshold: `phishing` ≥ 50, `suspicious` 35–50, `safe` < 35.

## Technical choices
Everything is our own code using open-source libraries with permissive licences (MIT/BSD/Apache), and every model
is trained by us from scratch. No outside AI service sees residents’ links.

| Part | Built with |
|---|---|
| Engine and model | Python, scikit-learn, LightGBM, tldextract, rapidfuzz |
| Server and live updates | FastAPI, WebSockets, SQLite |
| Police dashboard and resident app | Plain HTML/CSS/JS (no build step), installable web app with share target and QR scanning |
| DNS shield | dnslib |
| Android companion | Kotlin, Android notification listener and call-state APIs (`android/`) |
| Data | OpenPhish public feed, Phishing.Database, top-1M domains; optional PhiUSIIL (CC BY 4.0) and PhreshPhish |

## Run it
Python 3.10+.

```bash
pip install -r requirements.txt

# 1. data (only needed to retrain or refresh the threat lists; a trained model is included in models/)
python data/download.py             # feeds + top-1M + threat lists
python data/mine_uae_scams.py       # refresh data/uae_scam_urls.csv
python train.py                     # retrain (about 2 minutes); --mode url --csv data/raw/phiusiil_urls.csv for full URLs

# 2. the system
uvicorn server.app:app --host 0.0.0.0 --port 8000
#   police command centre:  http://localhost:8000/
#   resident app:           http://<laptop-ip>:8000/app   (or press "Connect phones" for a QR code)

# 3. optional DNS shield (point a test phone's DNS at the laptop)
python dns_shield.py --port 53 --api http://localhost:8000
```

### Scoring a list of URLs (hidden test set)
```bash
python predict.py urls.csv -o predictions.csv        # CSV with a url column, or a .txt with one URL per line
python predict.py urls.csv --live                    # also run live checks (needs internet)
python predict.py --url "http://tamm-abudhabi-fines.top/pay"
```
Output columns: `url, label (1 = phishing), verdict, risk_score, impersonated_brand, reasons_en, reasons_ar`.

### Other tools
```bash
python evaluate.py data/uae_eval.csv --no-threat-intel   # precision / recall / FPR on any labelled CSV
python hunter.py permute --brand tamm                     # registered look-alikes of a brand
python hunter.py crtsh --days 7                           # new certificates with UAE brand names
pytest -q                                                 # 26 tests
```

## API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | `{url, live}` → verdict, risk, brand, twin view, reasons |
| GET | `/api/check?url=` | quick check used by the phone app |
| POST | `/api/check-message` | `{text, report, emirate}` → links + scam-script signals (EN/AR) |
| GET | `/api/feed`, `/api/campaigns`, `/api/stats`, `/api/scamcast` | intelligence for the dashboard |
| POST | `/api/hunt` | `{mode: scamcast | permute | crtsh | replay}` runs a hunt in the background |
| POST / DELETE | `/api/antibody` | block / unblock a domain on every phone |
| GET | `/api/blocklist.txt?fmt=hosts` | blocklist for DNS filters |
| POST | `/api/evidence` | build an evidence pack; then `/api/evidence/{id}/report` and `/zip` |
| WS | `/ws` | live events: feed, antibody, report, hunt |

## Demo script (3 minutes)
1. **Hunt**: in the dashboard, press *Replay reported scams* (real UAE-targeted URLs stream in) or *ScamCast watchlist*.
2. **Explain**: open a site: twin view, reasons in Arabic and English, the brand it copies.
3. **Trace**: *Campaigns*: one Aramex kit across 17 domains; one kit hitting two UAE banks.
4. **Prevent**: judges scan the *Connect phones* QR; press *Block on every phone*; their phones show the alert.
5. **Guard**: on a phone, paste a fake Darb toll SMS → *Scam*; then the UAE PASS guard demo.
6. **Act**: *Create evidence pack* → case report and takedown zip.

## Repository layout
```
raqeeb/        engine: urlparse, features, brands (+ brands.json), model, engine, twin, messages,
               campaigns, scamcast, hunt, live, evidence, store
server/        FastAPI app (API + WebSocket + pages)
web/command/   police dashboard          web/app/   resident app (installable)
android/       Kotlin companion (notification scanning, UAE PASS guard, share target)
data/          download + mining scripts, UAE sanity set, mined UAE scam URLs
models/        trained model + threat lists      tests/   pytest suite
train.py  predict.py  evaluate.py  hunter.py  dns_shield.py
```

## Limitations
- Most scam sites hide behind CDNs or offshore hosting, so the visible IP is rarely the scammer. RAQEEB packages
  the evidence that police requests to registrars, hosts, banks and telecoms need.
- A dead site can only be judged from its URL; recall from the URL alone is the model’s weakest point.
- iOS can’t scan WhatsApp or run the UAE PASS guard; those are Android-only. The Android module was written for
  the hackathon and has not been compiled in CI.
- HTTPS sites blocked by the DNS shield show a browser error rather than RAQEEB’s warning page.
- Brand domains marked `check` in `brands.json` must be verified with each entity before production.
- New scam styles need the model retrained; `data/download.py` + `train.py` do this in minutes.

## Credits
Data: OpenPhish community feed, Phishing.Database (mitchellkrogza), top-1M domain list (zer0h); optional
PhiUSIIL (Prasad & Chandra, CC BY 4.0) and PhreshPhish (OpenText). UAE scam patterns from public advisories by
Abu Dhabi Police, Dubai Police, TDRA, ICP, Salik, Emirates Post, ADCB and Emirates NBD.
