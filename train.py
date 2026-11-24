"""Train the SAWNN URL model.

Data sources (see data/download.py):
  host mode (default): phishing URLs (OpenPhish + Phishing.Database) vs top legitimate domains.
                       The legit source only has domains, so the model learns from hostnames;
                       path signals are handled by the rule layer in the engine.
  url mode:           a labelled full-URL dataset (PhiUSIIL / PhreshPhish CSV with url,label columns),
                       which lets the model also learn from paths and queries.

Splits are grouped by registered domain so the same site never appears in train and test.
The decision threshold is chosen on a validation split to keep the false-positive rate under --max-fpr.
"""
import argparse
import json
import random
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit

from raqeeb.features import FEATURE_NAMES
from raqeeb.model import LGB_PARAMS, MODEL_DIR, Model, featurise, make_lr
from raqeeb.urlparse import parse

RAW = Path(__file__).parent / "data" / "raw"
# Most real legit URLs are the bare domain or www.; a minority use functional subdomains.
LEGIT_PREFIXES = [""] * 12 + ["www."] * 2 + ["m.", "app.", "my.", "online.", "portal.", "mail.", "account.",
                                             "login.", "secure.", "shop.", "support.", "help.", "api.", "news.", "blog."]


def read_lines(path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")]


def build_host_dataset(n_per_class, seed):
    rng = random.Random(seed)
    phish_urls = read_lines(RAW / "openphish.txt") + read_lines(RAW / "phishdb_links.txt")
    legit = read_lines(RAW / "top1m.txt") or read_lines(RAW / "top100k.txt")
    legit_set = set(legit)
    hosts = {}
    for u in phish_urls:
        if not u.lower().startswith(("http://", "https://")):
            continue
        h = parse(u).host
        if h and h not in legit_set and ("www." + h) not in legit_set and h.removeprefix("www.") not in legit_set:
            hosts[h] = 1
    phish_hosts = list(hosts)
    rng.shuffle(phish_hosts)
    phish_hosts = phish_hosts[:n_per_class]
    legit_hosts = set()
    phish_regs = {parse(h).registered_domain for h in phish_hosts}
    legit = [d for d in legit if d not in phish_regs]
    while len(legit_hosts) < min(n_per_class, len(legit) * 3):
        legit_hosts.add(rng.choice(LEGIT_PREFIXES) + rng.choice(legit))
    df = pd.DataFrame({"url": phish_hosts + list(legit_hosts),
                       "label": [1] * len(phish_hosts) + [0] * len(legit_hosts)})
    return df


def build_url_dataset(csv_path):
    df = pd.read_csv(csv_path)
    cols = {c.lower(): c for c in df.columns}
    df = df.rename(columns={cols["url"]: "url", cols["label"]: "label"})[["url", "label"]].dropna()
    # PhiUSIIL uses 1 = legitimate, 0 = phishing; PhreshPhish uses 'phish'/'benign'.
    if df["label"].dtype == object:
        df["label"] = df["label"].str.lower().isin(["phish", "phishing", "malicious", "1", "bad"]).astype(int)
    elif "phiusiil" in str(csv_path).lower():
        df["label"] = 1 - df["label"].astype(int)
    return df.drop_duplicates("url")


def pick_threshold(y, p, max_fpr):
    order = np.unique(np.round(p, 4))
    best = 0.5
    for t in order[::-1]:
        pred = p >= t
        fpr = ((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)
        if fpr <= max_fpr:
            best = t
        else:
            break
    return float(best)


def metrics(y, p, t):
    pred = (p >= t).astype(int)
    return {
        "precision": round(precision_score(y, pred), 4), "recall": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4),
        "fpr": round(float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)), 4),
        "roc_auc": round(roc_auc_score(y, p), 4), "pr_auc": round(average_precision_score(y, p), 4),
        "n": int(len(y)), "n_phish": int(y.sum()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["host", "url"], default="host")
    ap.add_argument("--csv", help="labelled CSV for url mode")
    ap.add_argument("--n", type=int, default=120000, help="samples per class (host mode)")
    ap.add_argument("--max-fpr", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    t0 = time.time()

    df = build_host_dataset(a.n, a.seed) if a.mode == "host" else build_url_dataset(a.csv)
    include_path = a.mode == "url"
    df["group"] = [parse(u).registered_domain or u for u in df["url"]]
    print(f"dataset: {len(df)} rows, {df.label.sum()} phishing, {df.group.nunique()} registered domains")

    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=a.seed)
    trval_idx, test_idx = next(outer.split(df, groups=df.group))
    trval, test = df.iloc[trval_idx].reset_index(drop=True), df.iloc[test_idx].reset_index(drop=True)
    inner = GroupShuffleSplit(n_splits=1, test_size=0.125, random_state=a.seed)
    tr_idx, val_idx = next(inner.split(trval, groups=trval.group))
    train, val = trval.iloc[tr_idx].reset_index(drop=True), trval.iloc[val_idx].reset_index(drop=True)

    Xtr, Ttr = featurise(train.url.tolist(), include_path)
    Xva, Tva = featurise(val.url.tolist(), include_path)
    Xte, Tte = featurise(test.url.tolist(), include_path)
    ytr, yva, yte = train.label.values, val.label.values, test.label.values

    # Out-of-fold LR probabilities so LightGBM never sees LR scores on rows LR was trained on.
    oof = np.zeros(len(train), dtype=np.float32)
    for f_tr, f_va in GroupKFold(n_splits=5).split(Ttr, ytr, groups=train.group):
        lr = make_lr().fit([Ttr[i] for i in f_tr], ytr[f_tr])
        oof[f_va] = lr.predict_proba([Ttr[i] for i in f_va])[:, 1]
    lr = make_lr().fit(Ttr, ytr)
    lr_va, lr_te = lr.predict_proba(Tva)[:, 1], lr.predict_proba(Tte)[:, 1]

    names = FEATURE_NAMES + ["lr_prob"]
    dtr = lgb.Dataset(np.column_stack([Xtr, oof]), ytr, feature_name=names)
    dva = lgb.Dataset(np.column_stack([Xva, lr_va]), yva, feature_name=names, reference=dtr)
    booster = lgb.train(LGB_PARAMS, dtr, num_boost_round=1500, valid_sets=[dva],
                        callbacks=[lgb.early_stopping(50, verbose=False)])

    p_va = booster.predict(np.column_stack([Xva, lr_va]))
    thr = pick_threshold(yva, p_va, a.max_fpr)
    p_te = booster.predict(np.column_stack([Xte, lr_te]))
    m_test = metrics(yte, p_te, thr)
    m_lr_only = metrics(yte, lr_te, 0.5)

    meta = {
        "mode": a.mode, "threshold": thr, "max_fpr_target": a.max_fpr, "trained_at": time.strftime("%Y-%m-%d %H:%M"),
        "rows": {"train": len(train), "val": len(val), "test": len(test)},
        "test_metrics": m_test, "test_metrics_lr_only@0.5": m_lr_only,
        "best_iteration": booster.best_iteration,
        "data_sources": (["OpenPhish public feed", "Phishing.Database ACTIVE links", "top-1M domains (zer0h)"]
                         if a.mode == "host" else [str(a.csv)]),
    }
    Model(lr, booster, meta).save(MODEL_DIR)
    print(json.dumps(meta, indent=2))
    print(f"done in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
