# SAWNN model and detection evaluation report

Every number in this report was produced by the scripts named next to it, on 24 November 2026, and is stored in
`models/evaluation_sawnn.json` (URL model) and `models/evaluation_verdicts.json` (end-to-end verdicts).
Nothing was estimated or rounded up. SAWNN does **not** reach the 99.9% target; the actual results and the next steps are below.

Reproduce:

```bash
python data/build_dataset.py                 # 1. versioned dataset          (~2 min)
python train_sawnn.py                         # 2. train + evaluate the model (~10 min, 2 CPUs)
git worktree add /tmp/old21 570ab57          # 3. RAQEEB 2.1 for the before/after comparison
python evaluate_sawnn.py --old /tmp/old21     # 4. end-to-end verdicts         (~2 min)
```

## 1. Why phishing sites were marked SAFE (root causes, all fixed)

| # | Cause in RAQEEB 2.1 | Fix in SAWNN | File |
|---|---|---|---|
| 1 | The model only saw the **hostname**. Phishing hosted in a path (`hacked-site.com/wp-content/dropbox/login`) looked identical to the legitimate site. Hostname recall was 52.8% on this test set. | New model reads the full canonical URL (host + path + query). | `train_sawnn.py`, `raqeeb/model.py`, `raqeeb/features.py` |
| 2 | **Popular-domain cap**: any registered domain in the top-10k list was capped at risk 20 (regional brand sites at 30), so phishing on Google Sites/Docs/Forms, SharePoint, Blogspot, hosting providers or hacked popular sites came out SAFE. `google.com` is the single largest phishing domain in the attached dataset (1,315 rows). | User-content platforms (Google Docs/Sites/Forms, SharePoint, OneDrive, Dropbox, cloud storage, hosting providers, site builders) never get the cap. A popular domain whose page the model flags at the strict operating point becomes SUSPICIOUS ("possible compromised page or open redirect"). | `raqeeb/engine.py` (`USER_CONTENT_HOSTS`, `user_content`) |
| 3 | **SAFE by default**: a low score with ML available returned SAFE even in a quick scan with no domain, sandbox or threat-intel evidence. | SAFE now needs positive evidence: an official-registry match, a well-established domain with a benign model result, a .gov.ae/.ac.ae/.sch.ae/.mil.ae restricted-zone domain, or a completed deep scan. Everything else is INCONCLUSIVE with the reason. Sandbox failure can never yield SAFE. | `raqeeb/link/risk.py`, `raqeeb/engine.py`, `raqeeb/messages.py` |
| 4 | A shortcut in the new data: in `url_dataset.csv` 99.8% of legitimate URLs start with `https://www.` but only 6.2% of phishing URLs use HTTPS. A model trained on raw URLs would learn "HTTPS = safe". | Every URL is canonicalised (no scheme, no leading `www.`) in training and in inference. | `raqeeb/features.py::canonical` |

Regression tests for each cause: `tests/test_sawnn.py` (`test_psl_brand_text_in_subdomain_is_not_official`,
`test_unknown_benign_looking_site_is_inconclusive_not_safe`, `test_phishing_on_user_content_platforms_is_not_capped_as_popular`,
`test_hosting_provider_subdomain_is_not_safe`, `test_sandbox_failure_never_yields_safe`, `test_canonical_form_removes_scheme_shortcut`).

## 2. The attached dataset (`url_dataset.csv`, the "Sentinel" archive)

| Property | Value |
|---|---|
| Records | 450,176 (columns `url`, `type`) |
| Labels | 345,738 `legitimate`, 104,438 `phishing` |
| Missing values | 0 |
| Duplicate URLs (exact) | 0 |
| Invalid URLs | 3 |
| Unique registered domains | 133,698 (89,391 in legitimate rows, 44,640 in phishing rows) |
| Domains appearing with both labels | 333 domains, 40,705 rows (mostly shared platforms: google.com, twitter.com, blogspot.com, box.com, windows.net …) |
| Phishing rows on top-10k popular domains | 4,547 (google.com 1,315, adnxs.com 255, twitter.com 217, fc2.com 176, bit.ly 175 …): plausible for redirects and hosted content, but these labels can't be checked without the original pages |
| Scheme artefact | legitimate rows 99.8% `https://www.`; phishing rows 6.2% HTTPS → removed by canonicalisation |
| Collection dates | none per row; file date 25 Jan 2025. No temporal split is possible from this file |
| Source / licence | not stated in the archive. The legitimate rows resemble an older web-directory crawl; treat provenance as unknown before any redistribution |
| Language | 113 rows contain Arabic script or punycode (103 phishing, 10 legitimate); otherwise Latin-script URLs |
| UAE share | 142 `.ae` URLs (132 phishing, 10 legitimate); about 277 rows mention UAE brands or places. **Very little UAE coverage** |

## 3. Training dataset `sawnn-ds-946b39760a`

Built by `data/build_dataset.py` (manifest: `data/processed/manifest.json`).

| Source | Label | Rows after cleaning |
|---|---|---|
| `url_dataset.csv` (attached) | legitimate | 345,600 |
| `url_dataset.csv` (attached) | phishing | 96,202 |
| Phishing.Database ACTIVE links | phishing | 770,037 |
| Phishing.Database hostnames | phishing | 149,999 |
| Top-1M domain list (hostnames) | legitimate | 150,000 |
| **Total distinct URLs** | | **1,511,838** from **494,915** registered domains |

Dropped: 681 invalid URLs, 8 URLs labelled both ways. The OpenPhish snapshot (299 URLs) is kept out of training as an unseen
fresh-threat set. The 10-million-record target is **not** met: 1.51M distinct records is what the available, legitimately usable
sources gave. The next sources to add are listed in section 8.

Training sample (to fit 2 CPUs / 8 GB): all attached-dataset rows, 180,000 Phishing.Database full URLs, 100,000 hostnames per
hostname source → 821,678 URLs. **Split by registered domain** (`GroupShuffleSplit`): 589,723 train / 77,359 validation /
154,596 test; no registered domain appears in more than one split (asserted in code).

## 4. Model

`sawnn-url-202611242052`: char 3–5-gram hashing + TF-IDF + logistic regression (out-of-fold, 3 folds) stacked into LightGBM
over 35 handcrafted URL features, then isotonic calibration on validation. Thresholds chosen on validation:
**0.8497** (validation FPR ≤ 1%, used for decisions) and **0.9726** (FPR ≤ 0.1%, used before questioning a popular domain).
Latency: 0.79 ms per URL (batch of 299).

## 5. Results on the held-out test split (154,596 URLs, 79,024 phishing, unseen domains)

Operating threshold 0.8497 unless stated.

| Model (same test set) | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|
| RAQEEB 2.1 hostname model (baseline) | 0.750 | 0.968 | 0.528 | 0.683 | 1.85% | 0.857 | 0.889 |
| Random Forest, handcrafted features | 0.708 | 0.992 | 0.433 | 0.603 | 0.35% | 0.906 | 0.927 |
| XGBoost, handcrafted features | 0.667 | 0.999 | 0.350 | 0.518 | 0.05% | 0.920 | 0.937 |
| Char n-gram LR only | 0.877 | 0.987 | 0.769 | 0.865 | 1.05% | 0.972 | 0.977 |
| **SAWNN stacked + calibrated (deployed)** | **0.879** | **0.997** | **0.766** | **0.866** | **0.25%** | **0.979** | **0.981** |
| SAWNN at 0.1%-FPR point (0.9726) | 0.786 | 1.000 | 0.581 | 0.735 | 0.02% | | |
| SAWNN at 0.5 | 0.921 | 0.979 | 0.864 | 0.918 | 1.97% | | |

Confusion matrix (deployed threshold): TN 75,382 · FP 190 · FN 18,499 · TP 60,525. FNR 23.4%.

Breakdown:

| Slice | n | Recall | FPR |
|---|---|---|---|
| URLs with a path or query | 91,970 | 0.871 | 0.19% |
| Hostname only | 62,626 | 0.628 | 0.35% |
| Attached dataset rows | 74,924 | 0.777 | 0.21% |
| Phishing.Database full URLs | 38,708 | 0.888 | – |
| Phishing.Database hostnames | 21,147 | 0.533 | – |
| Top-1M hostnames | 19,817 | – | 0.36% |
| **OpenPhish snapshot, unseen** | 299 | **0.833** (0.960 at 0.5) | – |
| UAE hand-labelled set, model only | 113 | 0.830 | 6.7% (4 of 60) |

## 6. End-to-end verdicts (what citizens and analysts actually see)

`evaluate_sawnn.py`: 2,500 phishing + 2,500 legitimate URLs drawn from the test split, quick scan, threat feeds **off**
(the test phishing URLs come from the same feeds, so leaving them on would measure a look-up). Same URLs for both versions.

| | Phishing → SAFE | Phishing → MALICIOUS/SUSPICIOUS | Legitimate → MALICIOUS/SUSPICIOUS | Legitimate → SAFE |
|---|---|---|---|---|
| RAQEEB 2.1 | **24.96%** | 74.8% | 15.5% | 84.5% |
| **SAWNN** | **0.12%** | 86.8% | 2.3% | 22.6% |
| SAWNN, UAE set (53 phishing / 60 legitimate) | 0.0% | 100% | 5.0% | 73.3% |

The rest is INCONCLUSIVE: 13.1% of phishing and 75.1% of legitimate URLs in a quick scan. That is the intended behaviour
of the SAWNN rule (unknown sites are not SAFE). A deep scan or an analyst resolves them.

## 7. Error analysis

* **Missed phishing (FN)** is concentrated in hostname-only entries (recall 0.63) and in short URLs on hosting platforms:
  the address alone carries little signal. These cases need the deep scan (page forms, redirects, visual comparison) and the
  threat feeds, which are on in production.
* **False positives** on modern legitimate URLs with short paths (e.g. `wam.ae/en`, `talabat.com/uae`): the attached dataset's
  legitimate full URLs are long, older directory-style links, so short modern paths are under-represented. Official-registry and
  popular-domain rules absorb most of these; three UAE sites remain SUSPICIOUS in the UAE set.
* The 3 phishing URLs still marked SAFE end-to-end are on well-established domains (label noise is possible).

## 8. Limitations and next steps

1. **Not 99.9%.** Measured recall at the operating point is 76.6% (URL model) and 86.8% flagged end-to-end on unseen domains.
2. Labels are from public feeds and the attached file; they were not manually re-verified.
3. No per-row timestamps, so no true temporal split; the OpenPhish snapshot is the closest fresh-threat check.
4. UAE coverage is thin (113-URL hand-labelled set). Next: collect verified UAE phishing from SAWNN analyst decisions
   (never raw citizen reports) and from abuse.ch/PhishTank once keys are configured.
5. Data to add toward 10M: Tranco list (legitimate domains, with research licence), Common Crawl URL index samples for
   legitimate full URLs with modern paths, PhishTank and URLhaus exports (free keys). Each needs licence review first.
6. Arabic vs English performance cannot be separated meaningfully: only 113 Arabic/IDN URLs exist in the data.
7. Visual and sandbox completion rates are not measured here: the build environment has no outbound network.
