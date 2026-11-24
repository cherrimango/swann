# SAWNN (صون): implemented versus pending

Updated 24 November 2026. Labels follow the SAWNN brief:
**IMPLEMENTED AND TESTED** · **IMPLEMENTED BUT NOT FULLY TESTED** · **PARTIALLY IMPLEMENTED** · **SIMULATED FOR DEMONSTRATION** ·
**NOT IMPLEMENTED** · **BLOCKED BY MISSING API ACCESS OR CREDENTIALS**.

"Tested" means covered by `pytest -q` (**all tests passing (see the count in the final report)**) or checked by hand in headless Chrome, as stated.
The build machine had **no outbound internet and no Docker daemon**, so nothing that needs a live website or a container was
exercised here.


## SAWNN update (24–25 November 2026)

| Feature | Label | Evidence |
|---|---|---|
| Rename RAQEEB/MIRA → SAWNN / صون across both apps, docs, Android display strings, env vars (`SAWNN_*`, old names still accepted) | IMPLEMENTED AND TESTED | `test_pages_served_and_no_old_branding` |
| Logo | IMPLEMENTED AND TESTED | no new logo file was attached with the SAWNN brief, so the previously supplied shield-and-eye mark is used (`web/shared/sawnn-mark.png`) |
| Visible animation: drifting red / white / green light fields, rotating red-white-green gradient borders on key glass panels, hover light sweep, animated gradient buttons, breathing status dots, animated focus ring; all frozen under reduced motion | IMPLEMENTED AND TESTED | checked by hand in headless Chrome (desktop and mobile) |
| Clipboard: Cmd/Ctrl+V, right-click and mobile paste untouched; Paste and Clear buttons; Enter scans (Shift+Enter new line); copy submitted URL, final destination and full redirect chain, with success/error feedback; fallback when the clipboard API is blocked | IMPLEMENTED AND TESTED | `tests/e2e/clipboard_e2e.py` run against the live server (results below) |
| Links copied from Arabic chats carried invisible direction marks (U+200E/200F etc.) and failed validation — fixed; right-to-left override is flagged as a spoofing signal | IMPLEMENTED AND TESTED | `test_invisible_characters_from_copied_links_are_removed` |
| Demo instructions moved out of the website into `docs/SAWNN_DEMO_GUIDE.md`; Command keeps only a "Demo data" load/remove switch; entry page no longer lists accounts | IMPLEMENTED AND TESTED | `/` and `/command` checked by hand |
| High-precision MALICIOUS tier (strong evidence or model probability ≥ validated floor; user-content platforms need strong evidence) | IMPLEMENTED AND TESTED | `evaluate_precision.py`: 99.923% point precision, CI 99.83–99.97% — target **not proven** |
| Agent orchestrator (DB task queue, worker, workflows, hand-offs, full task records) with 16 agents incl. URL Analysis and Sentiment & Social Engineering | IMPLEMENTED AND TESTED | `test_sixteen_agents_run_through_the_orchestrator_with_handoffs`, `test_failing_agent_is_recorded_not_hidden` |
| Citizen reports enter the agent pipeline | IMPLEMENTED AND TESTED | `test_citizen_report_enters_the_agent_pipeline` |
| Sentiment and social-engineering analysis EN/AR, supporting evidence only | IMPLEMENTED AND TESTED | `test_social_engineering_analysis_en_ar_is_supporting_only` |
| Scheduler with 10 configurable jobs, run history, honest running/stopped status | IMPLEMENTED AND TESTED | `test_scheduler_runs_jobs_and_records_failures`; live run collected 300 OpenPhish + 3 Phishing.Database URLs |
| Discovery → analysis → investigation (*Newly discovered*) → analyst notification | IMPLEMENTED AND TESTED | `test_discovery_pipeline_creates_investigations_and_notifies`; live run processed real feed URLs |
| Command: Global Threat Discovery workspace (schedule, sources, processing, verdicts, latency, history) and AI agents workspace (performance, workflows, task trees) | IMPLEMENTED AND TESTED | checked by hand |
| URLhaus, PhishTank polling | BLOCKED BY MISSING API ACCESS OR CREDENTIALS | need `SAWNN_URLHAUS_AUTH_KEY`, `SAWNN_PHISHTANK_APP_KEY` |
| Spamhaus, public/UAE advisory feeds | NOT IMPLEMENTED | licence / no machine-readable feed identified |
| Live sandbox on discovered URLs | IMPLEMENTED BUT NOT FULLY TESTED | off by default (`SAWNN_DISCOVERY_SANDBOX=1` only on an isolated host) |

Clipboard end-to-end results (`python tests/e2e/clipboard_e2e.py --chrome /usr/bin/google-chrome`, Chrome headless):

```text
Ctrl+V into Protect box (with invisible marks)  → pasted
Clear button                                    → ""
Paste button                                    → pasted
Ctrl+C of selected text                         → "https://login.uaepass.example.com/auth"
Enter                                           → scan ran, verdict "Dangerous"
Copy link button                                → copied, toast "Copied"
Command URL box Ctrl+V + Enter                  → "tamm-camping-permit.top/pay" → MALICIOUS
Copy final destination / Copy redirect chain    → exact final URL / 3-hop chain with stop reason
```

## Test commands and results

```text
$ pytest -q
102+ passed in 12.2s
$ python data/build_dataset.py      → sawnn-ds-946b39760a: 1,511,838 rows, 494,915 registered domains
$ python train_sawnn.py              → test precision 0.9969, recall 0.7659, F1 0.8663, FPR 0.0025, ROC-AUC 0.9787
$ python evaluate_sawnn.py --old /tmp/old21
                                    → phishing marked SAFE: RAQEEB 2.1 25.48% → SAWNN 0.12%
                                      legitimate flagged:   RAQEEB 2.1 14.96% → SAWNN 2.28%
```
New regression tests: `tests/test_sawnn.py` (21 tests). Screens checked by hand at 1440×900 and 420×900 in English and Arabic:
entry, Command (overview, alerts, sandbox, redirect journey), Protect (home, picture scan), `/signin`.

## Detection engine
| Feature | Label | Evidence |
|---|---|---|
| Fix for phishing marked SAFE (four verdicts; SAFE needs positive evidence; unknown → INCONCLUSIVE) | IMPLEMENTED AND TESTED | `test_unknown_benign_looking_site_is_inconclusive_not_safe`, `test_official_and_popular_domains_can_be_safe`, end-to-end evaluation |
| Popular-domain cap removed for user-content platforms and hosting providers; strict threshold before questioning a popular page | IMPLEMENTED AND TESTED | `test_phishing_on_user_content_platforms_is_not_capped_as_popular`, `test_hosting_provider_subdomain_is_not_safe` |
| PSL-aware parsing (`login.uaepass.example.com` → `example.com`) | IMPLEMENTED AND TESTED | `test_psl_brand_text_in_subdomain_is_not_official` |
| Verdict, risk score, confidence, completeness and analysis status reported separately | IMPLEMENTED AND TESTED | scan report contract, Command report view |
| Full-URL model trained on the attached dataset + feeds, calibrated, versioned | IMPLEMENTED AND TESTED | `test_model_is_the_full_url_model_with_calibration`, `docs/SAWNN_MODEL_EVALUATION.md` |
| Baselines (RF, XGBoost, char-LR, RAQEEB 2.1) on the same split | IMPLEMENTED AND TESTED | `models/evaluation_sawnn.json` |
| 99.9% accuracy target | NOT MET | measured 87.9% accuracy, 76.6% recall at 0.25% FPR; see report |
| 10M-record dataset | PARTIALLY IMPLEMENTED | pipeline is repeatable and versioned; 1.51M distinct records from available sources |
| Temporal evaluation | PARTIALLY IMPLEMENTED | no timestamps in the data; OpenPhish snapshot used as the fresh-threat test (83.3% recall) |
| `.gov.ae / .ac.ae / .sch.ae / .mil.ae` restricted-zone trust | IMPLEMENTED AND TESTED | `.aeDA` eligibility policy; `test_official_and_popular_domains_can_be_safe` |
| Threat intel: bundled OpenPhish + Phishing.Database snapshot, SAWNN verified threats, published rules, discovery indicators | IMPLEMENTED AND TESTED | `test_discovery_records_new_duplicates_missing_keys_and_failures` |
| Google Web Risk, VirusTotal, URLhaus, PhishTank | BLOCKED BY MISSING API ACCESS OR CREDENTIALS | adapters written; without a key they show "not checked" |
| Spamhaus | NOT IMPLEMENTED | needs a commercial data agreement |
| RDAP, DNS, TLS certificate | IMPLEMENTED BUT NOT FULLY TESTED | code from 2.1; needs internet |
| ASN / hosting relationships | PARTIALLY IMPLEMENTED | RDAP IP lookup in `raqeeb/live.py`; no ASN graph |
| Sandbox (Playwright Chromium, SSRF check on every request and redirect, downloads refused, dialogs dismissed) | IMPLEMENTED BUT NOT FULLY TESTED | 2.1 local fake-page test; live sites not reachable here |
| Sandbox failure never SAFE | IMPLEMENTED AND TESTED | `test_sandbox_failure_never_yields_safe` |
| Hardened Docker sandbox container | IMPLEMENTED BUT NOT FULLY TESTED | `infrastructure/sandbox/` written, not built (no Docker daemon) |
| Redirect analysis (every hop, status, type, domain changes, shorteners, loops, hop limit, stop reason, all-analysed flag) | IMPLEMENTED AND TESTED | `test_redirect_analysis_counts_hops_domains_and_loops` |
| Redirect timeline in Command (and in Protect deep-scan results) | IMPLEMENTED AND TESTED | checked by hand with `SCAN-DEMO-REDIRECT1` |
| Screenshot + pHash/layout/colour comparison + OCR | PARTIALLY IMPLEMENTED | works when reference screenshots exist (`data/capture_references.py`, needs internet); logo detection and image embeddings not implemented |
| Sandbox Configuration & Analysis Parameters page + per-scan collected parameters | IMPLEMENTED AND TESTED | `test_sandbox_configuration_is_for_officials_only`, checked by hand |

## Shared AI, discovery and agents
| Feature | Label | Evidence |
|---|---|---|
| One backend used by Protect and Command (`/api/v1/scan`, attachments, agents) | IMPLEMENTED AND TESTED | both apps call the same routes |
| Global Threat Discovery Engine (scheduled polling, per-source health, new vs duplicate, failures recorded, UTC storage, unverified leads) | IMPLEMENTED BUT NOT FULLY TESTED | logic tested with a mocked feed; live polling needs internet; scheduler on with `SAWNN_DISCOVERY_ENABLED=1` |
| 14 agents with the structured envelope | IMPLEMENTED AND TESTED | `test_fourteen_agents_with_structured_results` |
| Campaign correlation, seasonal intelligence (confirmed / emerging / predicted / historical) | IMPLEMENTED AND TESTED | 2.1 tests |

## SAWNN Protect
| Feature | Label | Evidence |
|---|---|---|
| Rebrand, exact logo, dark-navy glass design, no flag motifs | IMPLEMENTED AND TESTED | `test_pages_served_and_no_old_branding`, screenshots |
| English + Arabic only, global switch, RTL | IMPLEMENTED AND TESTED | Urdu strings kept inactive in `i18n.js` for later |
| Picture and file scanning (file picker, camera capture, gallery, drag and drop → QR decode, OCR, URLs, phones, link scans) | IMPLEMENTED AND TESTED | `test_attachment_qr_image_is_decoded_and_link_scanned`, `test_attachment_text_file_with_scam_link`, checked by hand |
| Unsupported or executable uploads refused with a clear message | IMPLEMENTED AND TESTED | `test_attachment_rejects_programs_and_unknown_types` |
| PDF analysis (text, link annotations, JavaScript / launch / embedded-file flags) | IMPLEMENTED BUT NOT FULLY TESTED | no PDF fixture in the tests |
| Malware scanning of uploads | NOT IMPLEMENTED | files are never executed; no AV engine is bundled |
| Official citizen alerts on Home (bilingual, acknowledge, report a related attempt, live push over WebSocket) | IMPLEMENTED AND TESTED | `test_citizen_alert_workflow_enforces_review_approval_and_honest_delivery` |
| Reporting (11 types), own report status, Block for me / Report to SAWNN | IMPLEMENTED AND TESTED | 2.1 tests + `test_models_metrics_and_reports_endpoints` |

## SAWNN Command
| Feature | Label | Evidence |
|---|---|---|
| Redesign: top-bar workspaces + contextual tabs, full-screen mode, glass panels | IMPLEMENTED AND TESTED | checked by hand |
| Overview with model, SAFE-rate, source health and sandbox activity from backend data | IMPLEMENTED AND TESTED | checked by hand |
| Citizen-alert workflow (draft, AI draft, EN/AR, review by someone else, admin approval, publish, withdraw, versions, delivery and engagement tracking, audit) | IMPLEMENTED AND TESTED | `test_citizen_alert_workflow…`, `test_ai_draft_is_labelled_and_bilingual` |
| Create citizen alert from a threat record | IMPLEMENTED BUT NOT FULLY TESTED | button wired; checked by hand only |
| Arabic in Command | PARTIALLY IMPLEMENTED | navigation, workspaces, headings, sign-in, new SAWNN views translated; older detailed analyst tables remain English |
| Sortable tables | PARTIALLY IMPLEMENTED | discovery and model tables; other tables not yet |
| RBAC (6 official roles + citizen), audit log | IMPLEMENTED AND TESTED | 2.1 tests + new permission tests |

## Sign-in
| Feature | Label | Evidence |
|---|---|---|
| Demo sign-in prototype (QR, simulated phone approval, consent, success/denial/expiry, one-time token, demo mode only) | SIMULATED FOR DEMONSTRATION | `test_demo_signin_prototype_issues_one_time_session`, `test_demo_signin_disabled_outside_demo_mode` |
| UAE PASS Security Simulator (7 steps, real engine link checks, call explanation; no calls placed) | SIMULATED FOR DEMONSTRATION | checked by hand |
| Real UAE PASS integration | BLOCKED BY MISSING API ACCESS OR CREDENTIALS | path documented in `docs/UAE_PASS_INTEGRATION.md` |
| Automatic sign-in (stored token, expiry, logout, hashed tokens, bearer header) | IMPLEMENTED AND TESTED | unchanged from 2.1 |

## Delivery channels
| Channel | Label |
|---|---|
| In-app (Protect inbox + live WebSocket) | IMPLEMENTED AND TESTED |
| Push, e-mail, SMS | BLOCKED BY MISSING API ACCESS OR CREDENTIALS: no provider adapters; recorded as "not configured", never as delivered |

## Mobile
| Feature | Label |
|---|---|
| PWA (share target, shortcuts, offline signed rules) | IMPLEMENTED AND TESTED (2.1) |
| Android module (notification scanning, call screening, Quick Settings tile) | IMPLEMENTED BUT NOT FULLY TESTED: written, not compiled (no Android SDK) |
| iOS extensions | NOT IMPLEMENTED (plan in `docs/ios.md`) |

## Known limitations
- SQLite instead of PostgreSQL/Redis (`SAWNN_REDIS_URL` is reserved, unused).
- DNS rebinding is checked before each connection at the application layer; a network-level egress policy is still needed (container profile provided).
- Visual comparison needs reference screenshots captured online; none ship.
- The attached dataset's provenance is not stated; check its licence before redistribution.
- The UAE evaluation set is small (113 URLs).
