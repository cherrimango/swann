# SAWNN (صون) — demonstration guide

This guide is for presenters. It is deliberately **not** part of the website: the applications contain no demo
instructions, only a "Demo data" switch for administrators. Everything marked *simulated* below is labelled the same
way in the interface.

## 1. Install (macOS)

Python **3.10 or newer** is required (3.12 recommended). Apple's built-in Python 3.9 will not work.

```bash
cd ~/Desktop/sawnn                    # the folder that contains requirements.txt
python3.12 -m venv .venv              # if missing: brew install python@3.12
source .venv/bin/activate             # the prompt now starts with (.venv)
python --version                      # must print 3.12.x
pip install -r requirements.txt
brew install libomp tesseract tesseract-lang     # libomp for the model; Tesseract for reading screenshots
pip install playwright && python -m playwright install chromium   # optional: live sandbox
```

## 2. Start

```bash
cd ~/Desktop/sawnn && source .venv/bin/activate
SAWNN_DEMO=1 uvicorn server.app:app --host 0.0.0.0 --port 8000
```

- Entry screen: http://localhost:8000/
- SAWNN Protect (citizens): http://localhost:8000/app
- SAWNN Command (officials): http://localhost:8000/command
- Sign-in prototype and security simulator: http://localhost:8000/signin
- API docs (Swagger): http://localhost:8000/docs
- Phones on the same Wi-Fi: Command → *Connect phones* shows a QR code for `http://<laptop-ip>:8000/app`.
  On plain `http` from another device, the browser blocks the *Paste* button (clipboard needs https or localhost);
  long-press paste still works.

The monitoring scheduler and the agent orchestrator start with the server. Set `SAWNN_SCHEDULER_ENABLED=0` to stop
the scheduler; Command will then show it as stopped.

## 3. Demo accounts (only when `SAWNN_DEMO=1`)

| Account | Password | Use |
|---|---|---|
| admin@sawnn.demo | SawnnDemo2026! | Command, Super Administrator (approves and publishes) |
| analyst@sawnn.demo | AnalystDemo2026! | Command, Cybercrime Analyst (verifies, drafts alerts) |
| citizen@sawnn.demo | CitizenDemo2026! | Protect |

**Login procedure:** open `/command`, click one of the *Demo accounts* buttons under the form (automatic sign-in) or
type the e-mail and password. For Protect, open `/app` → *Profile* → sign in. Or use the sign-in prototype (section 13).

**Load the demo data:** Command → Operations → *Demo data* → *Run steps 1–5*. This seeds the fictional
winter-camping scenario (`tamm-camping-permit.top`, `desertcamp-booking-tamm.top`, `+971500000001`), a synthetic
redirect sample `SCAN-DEMO-REDIRECT1`, and two citizen alerts in the approval workflow. Every seeded record is
labelled **Demo**; *Remove demo data* deletes all of it and leaves real data untouched.

## 4. URL scanning (real)

1. Protect → Home → paste `https://login.uaepass.example.com/auth` into the box. Cmd+V, right-click → Paste,
   the *Paste* button and mobile long-press all work. Press **Enter** (Shift+Enter adds a line).
2. The verdict sheet shows MALICIOUS/SUSPICIOUS with reasons: the address *contains* "uaepass" but belongs to
   `example.com` (Public Suffix List parsing). Use *Copy link* to copy the submitted URL.
3. Try `https://www.google.com` (SAFE: well-established domain) and an unknown site such as
   `https://quiet-garden-studio-portfolio.com` (INCONCLUSIVE, because SAWNN never calls an unknown site SAFE).
4. Command → Investigations → *Link & domain analysis*: paste the same URL, choose **Quick** or **Deep**.

## 5. Image and QR scanning (real)

Protect → Home → *Scan a picture* (or Protect → *Picture or file*). Drop a screenshot or a QR-code image, choose a
file, or *Take a photo* on a phone. SAWNN decodes QR codes (OpenCV), reads text (Tesseract, English + Arabic), extracts
links and phone numbers, scans every link, and analyses the text. Programs and archives are refused.
Make a test QR: `python -c "import qrcode; qrcode.make('http://uaepass-update-id.top/login').save('qr.png')"`.

## 6. Sandbox and redirect chains

- **Real (needs internet + Playwright):** Command → *Link & domain analysis* → **Deep** on a harmless site, e.g. a
  shortened link to a known page. Visit only controlled or harmless URLs from a normal laptop; never live phishing.
- **Synthetic sample (works offline):** Command → Investigations → *Sandbox configuration* → enter
  `SCAN-DEMO-REDIRECT1` → *Show collected parameters*. The redirect journey shows a shortener → tracker → fake page,
  domain changes and the stop reason. It is labelled *SYNTHETIC DEMO SAMPLE*.
- Copy buttons copy the submitted URL, the final destination and the whole chain.

## 7. Screenshot comparison

Real but needs reference screenshots of official sites: `python data/capture_references.py` (internet required). Deep
scans then report perceptual, layout and colour similarity per brand. Without references the report says
*visual comparison unavailable* — it never invents a score.

## 8. AI agents (real)

Command → Investigations → *AI agents*. Enter `http://adcb-secure-login.top/verify` in **URL Analysis** → *Run*.
The workflow appears as a task tree: URL Analysis → Phishing Intelligence → UAE Brand Impersonation → Campaign
Correlation, each with task ID, status, time, findings, evidence, confidence and hand-offs. *Recent workflows* lists
every workflow (including ones started by citizen reports and the scheduler); click one to open its chain.
Try **Sentiment & Social Engineering** with an Arabic message: `تم إيقاف حسابك. ادفع الغرامة خلال 24 ساعة`.

## 9. Threat discovery (real)

Command → Intelligence → *Global Threat Discovery Engine*. *Collect and analyse now* pulls OpenPhish and
Phishing.Database (no keys needed; needs internet), then the Global Threat Hunter queues an analysis for every new
indicator. Suspicious ones open a *Newly discovered* threat record and notify analysts. The schedule table shows the
real status of every job; without internet the feed jobs show *failed* with the network error, and that is correct.

## 10. Citizen reporting (real)

Protect → *Report* → paste a message, optionally attach a screenshot → send. The report gets a reference, enters the
agent pipeline (Message Intelligence + Sentiment + URL analysis), and appears in Command → *Citizen reports*. The
citizen can follow its status in Protect.

## 11. Official alert creation (real workflow, in-app delivery)

1. Sign in to Command as **analyst** → Response → *Citizen alerts* → *Create citizen alert* → *Draft with AI*
   (labelled AI-assisted) → edit English and Arabic → *Save draft* → *Send for review*.
2. Sign in as **admin** → open the alert → *Mark reviewed* → *Approve* → *Publish to citizens*.
3. Protect (citizen) shows the official alert on Home; *I've read this* records acknowledgement.
Push, e-mail and SMS are recorded as *not configured* — no provider adapters ship, so no delivery is claimed.

## 12. Arabic and English

Use the EN / ع switch on any screen. The whole interface turns right-to-left; the choice is remembered across pages.
Protect, the entry screen, the sign-in prototype and Command navigation, headings and the new SAWNN workspaces are
fully bilingual; some older analyst tables in Command remain English.

## 13. Sign-in prototype and UAE PASS security simulator (simulated)

`/signin` → *Sign-in prototype* → *Sign in with digital ID (demo)* → on the simulated phone choose an account, tick
consent, *Approve* → you land in Command or Protect. Nothing talks to UAE PASS; no real credentials are ever accepted.
*Security simulator* walks through seven fictional attacks; *Check this link with SAWNN* runs the real engine. The
call step is a written script — SAWNN never places calls.

## 14. What is real and what is simulated

| Real | Simulated / synthetic (labelled) |
|---|---|
| URL engine, model, verdicts, copy/paste, attachments, QR, OCR | Step 1 discovery of the winter-camping scenario |
| Agent orchestrator, hand-offs, task records | `SCAN-DEMO-REDIRECT1` redirect sample |
| Scheduler, feed collection (with internet), source health | Demo accounts and seeded alerts/reports |
| Citizen reports, alerts workflow, in-app delivery | Sign-in prototype and security simulator |
| Signed protection distribution, Block for me | Web UAE PASS guard on Protect (Android has the real one) |

Demo data never mixes with real intelligence: it is flagged `demo=1` (or `SCAN-DEMO-*`) and removed by *Remove demo data*.
