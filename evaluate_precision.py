"""Precision of SAWNN's MALICIOUS verdicts, measured on the domain-grouped held-out test split.

    python evaluate_precision.py --n 15000      # URLs per class (default 15,000)

Target: >= 99.9% precision for high-confidence MALICIOUS (verdict MALICIOUS with assessment confidence HIGH).
Reported with Wilson 95% confidence intervals, overall and per segment: global, UAE, Arabic, English, brand
impersonation, unseen domains (every test URL's registered domain is unseen in training by construction).
Threat-feed look-ups are off (the test phishing URLs come from those feeds). Precision depends on the share of
phishing in the data; the test sample is balanced, so the report also gives precision re-weighted to a 1% and 10%
phishing prevalence using the measured TPR and FPR.
Output: models/evaluation_precision.json
"""
import argparse
import json
import math
import re
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parent
WORKER = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import raqeeb.engine as E
E.threat_lists = lambda: (set(), set()); E._threat = (set(), set())
from raqeeb.link import signatures as S
S._feeds = lambda v: []
from raqeeb.link import pipeline as P
out = []
for u in json.load(open(sys.argv[2])):
    try:
        r = P.analyse(u, "quick")
        out.append([r["verdict"], r["assessment_confidence"], bool(r.get("detected_brand")), r["risk_score"]])
    except Exception as e:
        out.append(["ERROR", None, False, None])
json.dump(out, open(sys.argv[3], "w"))
'''
UAE_RX = re.compile(r"\.ae(\b|/|$)|uae|emirat|dubai|abudhabi|abu-dhabi|sharjah|ajman|fujairah|tamm|uaepass|salik|darb|adcb|enbd|"
                    r"mashreq|etisalat|aramex|emiratespost|mohre|gdrfa|icp", re.I)
AR_RX = re.compile(r"[؀-ۿ]|xn--")


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - h) / d, 5), round((c + h) / d, 5)]


def prec(y, flag):
    tp = int(((flag == 1) & (y == 1)).sum())
    fp = int(((flag == 1) & (y == 0)).sum())
    fn = int(((flag == 0) & (y == 1)).sum())
    tn = int(((flag == 0) & (y == 0)).sum())
    return {"n": int(len(y)), "n_phishing": int(y.sum()), "n_legitimate": int((y == 0).sum()), "flagged": tp + fp,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(tp / (tp + fp), 5) if tp + fp else None, "precision_ci95": wilson(tp, tp + fp),
            "recall": round(tp / (tp + fn), 4) if tp + fn else None, "fpr": round(fp / (fp + tn), 5) if fp + tn else None,
            "meets_99_9": (wilson(tp, tp + fp) or [0])[0] >= 0.999 if tp + fp else False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=15000)
    ap.add_argument("--workers", type=int, default=2)
    a = ap.parse_args()
    from train_sawnn import sample_and_split
    _, _, _, _, test = sample_and_split()
    rng = np.random.RandomState(11)
    sel = np.concatenate([rng.choice(np.where(test.label.values == c)[0], min(a.n, int((test.label.values == c).sum())), replace=False) for c in (1, 0)])
    sub = test.iloc[sel].reset_index(drop=True)
    urls = ["http://" + u for u in sub.url]
    import pandas as pd
    ue = pd.read_csv(ROOT / "data" / "uae_eval.csv")
    urls_all = urls + ue.url.tolist()
    t0 = time.time()
    chunks = np.array_split(np.arange(len(urls_all)), a.workers)
    procs = []
    scr = Path("/tmp/prec_worker.py"); scr.write_text(WORKER)
    for i, ch in enumerate(chunks):
        Path(f"/tmp/prec_in_{i}.json").write_text(json.dumps([urls_all[j] for j in ch]))
        env = {"PATH": "/usr/bin:/bin", "SAWNN_DB": f"/tmp/prec_{i}.db", "HOME": "/tmp", "SAWNN_SCHEDULER_ENABLED": "0"}
        procs.append(subprocess.Popen([sys.executable, str(scr), str(ROOT), f"/tmp/prec_in_{i}.json", f"/tmp/prec_out_{i}.json"], cwd=str(ROOT), env=env))
    for p in procs:
        p.wait()
    res = sum((json.loads(Path(f"/tmp/prec_out_{i}.json").read_text()) for i in range(len(chunks))), [])
    secs = time.time() - t0
    main_res, uae_res = res[:len(urls)], res[len(urls):]
    y = sub.label.values
    verdict = np.array([r[0] for r in main_res]); conf = np.array([r[1] or "" for r in main_res]); brand = np.array([r[2] for r in main_res])
    hc = ((verdict == "MALICIOUS") & (conf == "HIGH")).astype(int)
    mal = (verdict == "MALICIOUS").astype(int)
    seg = {
        "all (global, unseen domains)": np.ones(len(y), bool),
        "UAE-related URLs": np.array([bool(UAE_RX.search(u)) for u in sub.url]),
        "Arabic / IDN URLs": np.array([bool(AR_RX.search(u)) for u in sub.url]),
        "English / Latin-script URLs": np.array([not AR_RX.search(u) for u in sub.url]),
        "brand impersonation detected": brand,
        "with path or query": np.array(["/" in u or "?" in u for u in sub.url]),
        "hostname only": np.array(["/" not in u and "?" not in u for u in sub.url]),
    }
    out = {"generated": time.strftime("%Y-%m-%d %H:%M"), "seconds": round(secs, 1), "test_split": "domain-grouped held-out (train_sawnn.sample_and_split)",
           "threat_feeds": "off", "definition": "high-confidence MALICIOUS = verdict MALICIOUS and assessment_confidence HIGH",
           "high_confidence_malicious": {k: prec(y[m], hc[m]) for k, m in seg.items()},
           "any_malicious": {k: prec(y[m], mal[m]) for k, m in seg.items()},
           "verdict_counts": {lab: {v: int(((verdict == v) & (y == c)).sum()) for v in ("MALICIOUS", "SUSPICIOUS", "INCONCLUSIVE", "SAFE", "ERROR")}
                              for lab, c in (("phishing", 1), ("legitimate", 0))}}
    allp = out["high_confidence_malicious"]["all (global, unseen domains)"]
    tpr, fpr = allp["recall"] or 0, allp["fpr"] or 0
    out["precision_at_prevalence"] = {f"{int(p * 100)}%": round(tpr * p / (tpr * p + fpr * (1 - p)), 5) if tpr * p + fpr * (1 - p) else None for p in (0.01, 0.1, 0.5)}
    uy = ue.label.values
    uv = np.array([r[0] for r in uae_res]); uc = np.array([r[1] or "" for r in uae_res])
    out["uae_hand_labelled_set"] = {"high_confidence_malicious": prec(uy, ((uv == "MALICIOUS") & (uc == "HIGH")).astype(int)),
                                    "any_malicious": prec(uy, (uv == "MALICIOUS").astype(int)),
                                    "note": "113 URLs; 53 phishing are synthetic UAE look-alikes. Far too small to prove 99.9%."}
    fps = [sub.url[i] for i in range(len(y)) if hc[i] == 1 and y[i] == 0]
    out["false_positives_high_confidence"] = fps[:50]
    out["false_negatives_sample"] = [sub.url[i] for i in range(len(y)) if y[i] == 1 and verdict[i] == "SAFE"][:30]
    (ROOT / "models" / "evaluation_precision.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: {m: v[m] for m in ("n", "flagged", "tp", "fp", "precision", "precision_ci95", "recall", "meets_99_9")}
                      for k, v in out["high_confidence_malicious"].items()}, indent=1))
    print("prevalence", out["precision_at_prevalence"], "fps", fps[:20], f"{secs:.0f}s")


if __name__ == "__main__":
    main()
