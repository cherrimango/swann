"""Evaluate the full RAQEEB engine on any labelled CSV (url,label with 1 = phishing).

    python evaluate.py data/uae_eval.csv
    python evaluate.py data/raw/phiusiil_urls.csv --sample 20000 --no-threat-intel
"""
import argparse
import json

import pandas as pd

from raqeeb.engine import scan_many


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--sample", type=int)
    ap.add_argument("--no-threat-intel", action="store_true", help="measure detection without feed look-ups")
    ap.add_argument("--show-errors", type=int, default=15)
    a = ap.parse_args()
    df = pd.read_csv(a.csv)
    if a.sample and len(df) > a.sample:
        df = df.sample(a.sample, random_state=0)
    res = []
    urls = df.url.astype(str).tolist()
    for i in range(0, len(urls), 5000):
        res += scan_many(urls[i:i + 5000], use_threat_intel=not a.no_threat_intel)
    df["pred"] = [r["label"] for r in res]
    df["risk"] = [r["risk_score"] for r in res]
    y, p = df.label.astype(int), df.pred
    tp, fp = int(((p == 1) & (y == 1)).sum()), int(((p == 1) & (y == 0)).sum())
    fn, tn = int(((p == 0) & (y == 1)).sum()), int(((p == 0) & (y == 0)).sum())
    prec, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    out = {"n": len(df), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4), "recall": round(rec, 4),
           "f1": round(2 * prec * rec / max(prec + rec, 1e-9), 4), "fpr": round(fp / max(fp + tn, 1), 4),
           "threat_intel": not a.no_threat_intel}
    print(json.dumps(out, indent=2))
    errs = df[df.pred != df.label].sort_values("risk")
    if len(errs):
        print("\nerrors:")
        for _, r in errs.head(a.show_errors).iterrows():
            print(f"  label={r.label} risk={r.risk:5}  {r.url}")


if __name__ == "__main__":
    main()
