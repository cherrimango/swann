"""Choose the model-probability floor for the MALICIOUS verdict on the VALIDATION split (never on test).

MALICIOUS is kept for URLs with strong independent evidence (signature match, brand impersonation in the host,
credential page impersonating a brand, visual clone, IP address with login wording) or whose calibrated model
probability is at least threshold_malicious. Everything else at high risk becomes SUSPICIOUS, which still warns the
user. The floor is the lowest value whose MALICIOUS precision on validation is >= 99.9%; the held-out test then checks it.

    python tune_malicious_threshold.py --n 15000     # writes threshold_malicious into models/meta.json
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

from evaluate_precision import wilson

ROOT = Path(__file__).parent
STRONG = {"brand_impersonation", "typosquat", "brand_credential_page", "visual_clone", "ip_with_lures"}
WORKER = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import os; os.environ["SAWNN_MALICIOUS_FLOOR"] = "0.0"
import raqeeb.engine as E
E.threat_lists = lambda: (set(), set()); E._threat = (set(), set())
from raqeeb.link import signatures as S
S._feeds = lambda v: []
from raqeeb.link import pipeline as P
out = []
for u in json.load(open(sys.argv[2])):
    r = P.analyse(u, "quick")
    out.append([r["verdict"], r["ml_result"].get("probability"), [e["signal"] for e in r["evidence"] if e["direction"] == "risk"]])
json.dump(out, open(sys.argv[3], "w"))
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=15000)
    a = ap.parse_args()
    from train_sawnn import sample_and_split
    _, _, _, val, _ = sample_and_split()
    rng = np.random.RandomState(5)
    sel = np.concatenate([rng.choice(np.where(val.label.values == c)[0], min(a.n, int((val.label.values == c).sum())), replace=False) for c in (1, 0)])
    sub = val.iloc[sel].reset_index(drop=True)
    urls = ["http://" + u for u in sub.url]
    scr = Path("/tmp/tune_worker.py"); scr.write_text(WORKER)
    chunks = np.array_split(np.arange(len(urls)), 2)
    procs = []
    for i, ch in enumerate(chunks):
        Path(f"/tmp/tune_in_{i}.json").write_text(json.dumps([urls[j] for j in ch]))
        env = {"PATH": "/usr/bin:/bin", "SAWNN_DB": f"/tmp/tune_{i}.db", "HOME": "/tmp", "SAWNN_SCHEDULER_ENABLED": "0", "SAWNN_MALICIOUS_FLOOR": "0"}
        procs.append(subprocess.Popen([sys.executable, str(scr), str(ROOT), f"/tmp/tune_in_{i}.json", f"/tmp/tune_out_{i}.json"], cwd=str(ROOT), env=env))
    for p in procs:
        p.wait()
    res = sum((json.loads(Path(f"/tmp/tune_out_{i}.json").read_text()) for i in range(2)), [])
    y = sub.label.values
    mal = np.array([r[0] == "MALICIOUS" for r in res])
    prob = np.array([r[1] if r[1] is not None else 0 for r in res])
    strong = np.array([bool(set(r[2]) & STRONG) for r in res])
    table, chosen = [], None
    for t in np.round(np.arange(0.85, 1.0, 0.0005), 4):
        flag = mal & (strong | (prob >= t))
        tp, fp = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum())
        lo = (wilson(tp, tp + fp) or [0])[0]
        table.append({"threshold": float(t), "flagged": tp + fp, "tp": tp, "fp": fp, "precision": round(tp / max(tp + fp, 1), 5),
                      "ci95_low": lo, "recall": round(tp / max(int(y.sum()), 1), 4)})
        if chosen is None and tp + fp and tp / (tp + fp) >= 0.999:
            chosen = float(t)
    meta_p = ROOT / "models" / "meta.json"
    meta = json.loads(meta_p.read_text())
    meta["threshold_malicious"] = chosen
    meta["threshold_malicious_tuning"] = {"split": "validation", "n_per_class": a.n, "rule": "MALICIOUS needs strong evidence or model probability >= threshold_malicious",
                                          "target": "lowest threshold with validation precision >= 0.999 (point estimate); the test split then checks it independently", "table": table}
    meta_p.write_text(json.dumps(meta, indent=2))
    print("chosen", chosen)
    for r in table[::10]:
        print(r)


if __name__ == "__main__":
    main()
