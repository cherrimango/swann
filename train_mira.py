"""Train MIRA's full-URL model on the versioned dataset from data/build_dataset.py and write an honest evaluation.

    python data/build_dataset.py      # once: builds data/processed/<version>.csv.gz
    python train_mira.py              # trains, evaluates, writes models/ and models/evaluation_mira.json

Design:
- Every URL is put in canonical form (no scheme, no leading www.) so "https" cannot act as a label shortcut.
- Splits are grouped by registered domain: no site appears in more than one of train / validation / test.
- Stage 1: char 3-5-gram logistic regression (out-of-fold scores for stage 2). Stage 2: LightGBM over 35
  handcrafted URL features + the stage-1 score. Probabilities are calibrated with isotonic regression on validation.
- Decision threshold: highest recall with validation FPR <= --max-fpr (default 1%).
- Baselines on the same split: char-LR only, Random Forest and XGBoost on handcrafted features, and the previous
  MIRA 2.1 hostname-only model (models_v21_host/), so improvement is measured, not asserted.
- Extra test sets never used in training: the OpenPhish snapshot (fresh phishing) and data/uae_eval.csv.
"""
import argparse
import json
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit

from raqeeb.features import FEATURE_NAMES, canonical
from raqeeb.model import LGB_PARAMS, MODEL_DIR, Model, featurise, make_lr
from raqeeb.urlparse import parse

ROOT = Path(__file__).parent
PROC = ROOT / "data" / "processed"


def pick_threshold(y, p, max_fpr):
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(max_fpr * len(neg)))
    return float(np.nextafter(neg[k], 1)) if k < len(neg) else 0.5


def metrics(y, p, t):
    pred = (p >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"threshold": round(float(t), 4), "accuracy": round((tp + tn) / len(y), 4),
           "precision": round(precision_score(y, pred, zero_division=0), 4), "recall": round(recall_score(y, pred, zero_division=0), 4),
           "f1": round(f1_score(y, pred, zero_division=0), 4), "fpr": round(fp / max(fp + tn, 1), 4), "fnr": round(fn / max(fn + tp, 1), 4),
           "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "n": int(len(y)), "n_phish": int(y.sum())}
    if 0 < y.sum() < len(y):
        out["roc_auc"] = round(roc_auc_score(y, p), 4)
        out["pr_auc"] = round(average_precision_score(y, p), 4)
    return out


def sample_and_split(dataset=None, cap_phishdb=180_000, cap_hosts=100_000, seed=42):
    """Deterministic sample + domain-grouped split, shared by train_mira.py and evaluate_mira.py."""
    man = json.loads((PROC / "manifest.json").read_text())
    path = Path(dataset) if dataset else ROOT / man["file"]
    df = pd.read_csv(path)
    rng = np.random.RandomState(seed)
    parts = []
    for src, g in df.groupby("source"):
        cap = cap_phishdb if src == "Phishing.Database" else cap_hosts if "(hostname)" in src else None
        parts.append(g.sample(n=min(cap, len(g)), random_state=rng) if cap else g)
    df = pd.concat(parts).sample(frac=1, random_state=rng).reset_index(drop=True)
    df["url"] = [canonical(u) for u in df.url]
    df = df.drop_duplicates("url").reset_index(drop=True)
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    trval_i, te_i = next(outer.split(df, groups=df.group))
    trval, test = df.iloc[trval_i].reset_index(drop=True), df.iloc[te_i].reset_index(drop=True)
    inner = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=seed)
    tr_i, va_i = next(inner.split(trval, groups=trval.group))
    train, val = trval.iloc[tr_i].reset_index(drop=True), trval.iloc[va_i].reset_index(drop=True)
    assert not (set(train.group) & set(test.group)) and not (set(val.group) & set(test.group))
    return man, df, train, val, test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--cap-phishdb", type=int, default=180_000)
    ap.add_argument("--cap-hosts", type=int, default=100_000)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    t0 = time.time()
    man, df, train, val, test = sample_and_split(a.dataset, a.cap_phishdb, a.cap_hosts, a.seed)
    print(f"[{time.time()-t0:.0f}s] training sample {len(df)} rows, {df.label.sum()} phishing, {df.group.nunique()} domains", flush=True)
    rng = np.random.RandomState(a.seed + 1)

    Xtr, Ttr = featurise(train.url.tolist(), True)
    Xva, Tva = featurise(val.url.tolist(), True)
    Xte, Tte = featurise(test.url.tolist(), True)
    ytr, yva, yte = train.label.values, val.label.values, test.label.values
    print(f"[{time.time()-t0:.0f}s] features done", flush=True)

    oof = np.zeros(len(train), dtype=np.float32)
    for k, (f_tr, f_va) in enumerate(GroupKFold(n_splits=3).split(Ttr, ytr, groups=train.group)):
        lr = make_lr().fit([Ttr[i] for i in f_tr], ytr[f_tr])
        oof[f_va] = lr.predict_proba([Ttr[i] for i in f_va])[:, 1]
        print(f"[{time.time()-t0:.0f}s] LR fold {k} done", flush=True)
    lr = make_lr().fit(Ttr, ytr)
    lr_va, lr_te = lr.predict_proba(Tva)[:, 1], lr.predict_proba(Tte)[:, 1]
    print(f"[{time.time()-t0:.0f}s] LR full done", flush=True)

    names = FEATURE_NAMES + ["lr_prob"]
    dtr = lgb.Dataset(np.column_stack([Xtr, oof]), ytr, feature_name=names)
    dva = lgb.Dataset(np.column_stack([Xva, lr_va]), yva, feature_name=names, reference=dtr)
    booster = lgb.train(LGB_PARAMS, dtr, num_boost_round=2000, valid_sets=[dva], callbacks=[lgb.early_stopping(50, verbose=False)])
    raw_va = booster.predict(np.column_stack([Xva, lr_va]))
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw_va, yva)
    cal = {"x": [round(float(v), 6) for v in iso.X_thresholds_], "y": [round(float(v), 6) for v in iso.y_thresholds_]}
    p_va = np.interp(raw_va, cal["x"], cal["y"])
    p_te = np.interp(booster.predict(np.column_stack([Xte, lr_te])), cal["x"], cal["y"])
    thr = pick_threshold(yva, p_va, a.max_fpr)
    thr_strict = pick_threshold(yva, p_va, 0.001)
    print(f"[{time.time()-t0:.0f}s] LightGBM done, iteration {booster.best_iteration}", flush=True)

    ev = {"main": metrics(yte, p_te, thr), "strict_0.1pct_fpr": metrics(yte, p_te, thr_strict), "at_0.5": metrics(yte, p_te, 0.5)}
    ev["by_source"] = {s: metrics(yte[m], p_te[m], thr) for s in test.source.unique() for m in [(test.source == s).values]}
    ev["with_path_vs_hostname_only"] = {
        k: metrics(yte[m], p_te[m], thr) for k, m in
        {"with_path": np.array(["/" in u or "?" in u for u in test.url]), "hostname_only": np.array(["/" not in u and "?" not in u for u in test.url])}.items()}

    # Baselines on the same split
    base = {"char_lr_only": metrics(yte, lr_te, pick_threshold(yva, lr_va, a.max_fpr))}
    try:
        import xgboost as xgb
        xg = xgb.XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.9, tree_method="hist", n_jobs=2)
        xg.fit(Xtr, ytr)
        base["xgboost_handcrafted"] = metrics(yte, xg.predict_proba(Xte)[:, 1], pick_threshold(yva, xg.predict_proba(Xva)[:, 1], a.max_fpr))
    except Exception as e:  # noqa: BLE001
        base["xgboost_handcrafted"] = {"error": str(e)}
    sub = rng.choice(len(Xtr), size=min(200_000, len(Xtr)), replace=False)
    rf = RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=2, random_state=a.seed).fit(Xtr[sub], ytr[sub])
    base["random_forest_handcrafted"] = metrics(yte, rf.predict_proba(Xte)[:, 1], pick_threshold(yva, rf.predict_proba(Xva)[:, 1], a.max_fpr))
    old_dir = ROOT / "models_v21_host"
    if old_dir.exists():
        old = Model.load(old_dir)
        base["raqeeb_2_1_hostname_model"] = metrics(yte, old.predict(test.url.tolist())[0], old.threshold)
    ev["baselines_same_test_set"] = base
    print(f"[{time.time()-t0:.0f}s] baselines done", flush=True)

    meta = {"mode": "url", "canonical": True, "calibration": cal, "threshold": round(thr, 6), "threshold_strict": round(thr_strict, 6),
            "max_fpr_target": a.max_fpr, "trained_at": time.strftime("%Y-%m-%d %H:%M"), "model_version": f"mira-url-{time.strftime('%Y%m%d%H%M')}",
            "dataset_version": man["version"], "rows": {"train": len(train), "val": len(val), "test": len(test)},
            "test_metrics": ev["main"], "best_iteration": booster.best_iteration,
            "data_sources": sorted(df.source.unique().tolist()),
            "training_config": {"lr": "char 3-5 gram hashing(2^19) + tfidf + LogisticRegression(C=4, liblinear)",
                                "lgbm": LGB_PARAMS, "oof_folds": 3, "calibration": "isotonic on validation",
                                "caps": {"Phishing.Database": a.cap_phishdb, "hostname rows": a.cap_hosts}, "seed": a.seed}}
    model = Model(lr, booster, meta)
    model.save(MODEL_DIR)

    # Held-out sets never used in training
    fresh = [l for l in (PROC / "openphish_fresh.txt").read_text().split() if l]
    seen = set(df.url)
    fresh = [u for u in fresh if canonical(u) not in seen]
    if fresh:
        t1 = time.time()
        pf = model.predict(fresh)[0]
        ev["openphish_fresh_unseen"] = {"n": len(fresh), "recall_at_threshold": round(float((pf >= thr).mean()), 4),
                                        "recall_at_0.5": round(float((pf >= 0.5).mean()), 4),
                                        "latency_ms_per_url": round((time.time() - t1) * 1000 / len(fresh), 3)}
    ue = pd.read_csv(ROOT / "data" / "uae_eval.csv")
    pu = model.predict(ue.url.tolist())[0]
    ev["uae_eval_model_only"] = metrics(ue.label.values, pu, thr)
    ev["uae_eval_model_only"]["misclassified"] = [
        {"url": u, "label": int(y), "p": round(float(p), 3)} for u, y, p in zip(ue.url, ue.label, pu) if (p >= thr) != bool(y)]
    out = {"model_version": meta["model_version"], "dataset_version": man["version"], "dataset_manifest": "data/processed/manifest.json",
           "split": "GroupShuffleSplit by registered domain: 70% train / 10% validation / 20% test", "evaluation": ev,
           "limitations": [
               "Labels come from public feeds and the attached dataset; they were not manually re-verified.",
               "Legitimate full URLs come from a single source (url_dataset.csv) whose style differs from the phishing feeds; some separation may reflect source style.",
               "No timestamps in the attached dataset, so a true temporal split is not possible; the OpenPhish snapshot is the closest fresh-threat check.",
               "UAE evaluation set is small (113 URLs) and hand-labelled.",
               "These are URL-only metrics. Deep scans add DNS, TLS, sandbox and visual evidence that this table does not measure."]}
    (MODEL_DIR / "evaluation_mira.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: ev[k] for k in ("main", "strict_0.1pct_fpr")}, indent=1))
    print(json.dumps({k: {m: v.get(m) for m in ("recall", "fpr", "f1", "roc_auc")} for k, v in base.items()}, indent=1))
    print(json.dumps({k: ev[k] for k in ("openphish_fresh_unseen",) if k in ev}), ev["uae_eval_model_only"]["recall"], ev["uae_eval_model_only"]["fpr"])
    print(f"done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
