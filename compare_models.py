"""Compare MIRA's production model (char n-gram LR stacked into LightGBM) with a Random Forest baseline and
XGBoost, on exactly the same data and the same domain-grouped split as train.py.

Nothing is deployed by this script: it writes the measured results to models/evaluation.json so they can be shown
as they are. The decision threshold for every model is picked on the validation split for FPR <= --max-fpr.

    python compare_models.py            # needs data/raw from data/download.py; about 5 minutes
"""
import argparse
import json
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit

from raqeeb.features import FEATURE_NAMES
from raqeeb.model import MODEL_DIR, Model, featurise
from raqeeb.urlparse import parse
from train import build_host_dataset, pick_threshold


def full_metrics(y, p, t, seconds, n):
    pred = (p >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(t), 4), "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4), "recall": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4), "roc_auc": round(roc_auc_score(y, p), 4),
        "pr_auc": round(average_precision_score(y, p), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4), "false_negative_rate": round(fn / max(fn + tp, 1), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "latency_ms_per_url": round(1000 * seconds / max(n, 1), 4),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150000, help="per class; must match train.py so the test split is identical")
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    t0 = time.time()

    df = build_host_dataset(a.n, a.seed)
    df["group"] = [parse(u).registered_domain or u for u in df["url"]]
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=a.seed)
    trval_idx, test_idx = next(outer.split(df, groups=df.group))
    trval, test = df.iloc[trval_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)
    inner = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=a.seed)
    tr_idx, val_idx = next(inner.split(trval, groups=trval.group))
    train, val = trval.iloc[tr_idx].reset_index(drop=True), trval.iloc[val_idx].reset_index(drop=True)
    assert not set(train.group) & set(test.group), "domain leakage between train and test"

    Xtr, _ = featurise(train.url.tolist(), False)
    Xva, _ = featurise(val.url.tolist(), False)
    Xte, _ = featurise(test.url.tolist(), False)
    ytr, yva, yte = train.label.values, val.label.values, test.label.values
    results = {}

    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=3, n_jobs=-1, random_state=a.seed).fit(Xtr, ytr)
    thr = pick_threshold(yva, rf.predict_proba(Xva)[:, 1], a.max_fpr)
    s = time.time(); p = rf.predict_proba(Xte)[:, 1]
    results["random_forest_baseline"] = full_metrics(yte, p, thr, time.time() - s, len(yte))

    try:
        import xgboost as xgb
        xg = xgb.XGBClassifier(n_estimators=1500, learning_rate=0.05, max_depth=8, subsample=0.9, colsample_bytree=0.8,
                               eval_metric="logloss", early_stopping_rounds=50, n_jobs=-1, random_state=a.seed)
        xg.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)
        thr = pick_threshold(yva, xg.predict_proba(Xva)[:, 1], a.max_fpr)
        s = time.time(); p = xg.predict_proba(Xte)[:, 1]
        results["xgboost"] = full_metrics(yte, p, thr, time.time() - s, len(yte))
    except ImportError:
        results["xgboost"] = {"available": False, "reason": "pip install xgboost"}

    prod = Model.load()
    s = time.time(); p, _, _ = prod.predict(test.url.tolist())
    results["production_lr_lightgbm_stack"] = full_metrics(yte, np.asarray(p), prod.threshold, time.time() - s, len(yte))

    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "dataset": {"rows": len(df), "phishing": int(df.label.sum()), "legitimate": int((df.label == 0).sum()),
                    "sources": ["OpenPhish public feed", "Phishing.Database", "top-1M domains (legitimate)"],
                    "features": f"{len(FEATURE_NAMES)} hostname features (+ char n-gram LR for the production stack)"},
        "split": {"method": "grouped by registered domain (no domain appears in both train and test)",
                  "train": len(train), "validation": len(val), "test": len(test)},
        "threshold_rule": f"chosen on validation for false-positive rate <= {a.max_fpr}",
        "results": results,
        "notes": ["Hostname-only evaluation: the legitimate source lists domains, not full URLs.",
                  "Not a temporal split: the public feeds do not carry reliable first-seen dates for every URL.",
                  "The production model was trained on the same split seed, so its test rows were unseen in training."],
        "seconds": round(time.time() - t0),
    }
    (MODEL_DIR / "evaluation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
