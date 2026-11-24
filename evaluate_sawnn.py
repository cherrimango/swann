"""End-to-end evaluation of SAWNN's verdicts (not just the model) on the held-out test split, plus a before/after
comparison with RAQEEB 2.1 on exactly the same URLs.

    python evaluate_sawnn.py                      # new engine only
    python evaluate_sawnn.py --old /tmp/old21     # also run RAQEEB 2.1 from a git worktree of commit 570ab57

Threat-feed look-ups are switched off for this measurement: the phishing test URLs come from the same feeds that SAWNN
uses for signature matching, so leaving them on would measure a list look-up, not detection. In production the feeds
are on and catch every listed URL.

Output: models/evaluation_verdicts.json
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parent
SCRIPT = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import raqeeb.engine as E
E.threat_lists = lambda: (set(), set())
E._threat = (set(), set())
from raqeeb.link import signatures as S
S._feeds = lambda v: []
from raqeeb.link import pipeline as P
out = []
for u in json.load(open(sys.argv[2])):
    try:
        r = P.analyse(u, "quick")
        out.append(r["verdict"])
    except Exception as e:
        out.append("ERROR:" + str(e)[:60])
json.dump(out, open(sys.argv[3], "w"))
'''


def run(code_dir: Path, urls: list[str], tag: str) -> list[str]:
    inp, outp, scr = Path(f"/tmp/eval_{tag}_in.json"), Path(f"/tmp/eval_{tag}_out.json"), Path(f"/tmp/eval_{tag}.py")
    inp.write_text(json.dumps(urls))
    scr.write_text(SCRIPT)
    env = {"PATH": "/usr/bin:/bin", "SAWNN_DB": f"/tmp/eval_{tag}.db", "RAQEEB_DB": f"/tmp/eval_{tag}.db", "HOME": "/tmp"}
    subprocess.run([sys.executable, str(scr), str(code_dir), str(inp), str(outp)], cwd=str(code_dir), env=env, check=True)
    return json.loads(outp.read_text())


def table(verdicts, labels):
    out = {}
    for name, y in (("phishing", 1), ("legitimate", 0)):
        v = [x for x, l in zip(verdicts, labels) if l == y]
        out[name] = {k: round(v.count(k) / max(len(v), 1), 4) for k in ("MALICIOUS", "SUSPICIOUS", "INCONCLUSIVE", "SAFE")}
        out[name]["n"] = len(v)
    ph = out["phishing"]
    lg = out["legitimate"]
    out["phishing_marked_safe"] = ph["SAFE"]
    out["phishing_flagged_malicious_or_suspicious"] = round(ph["MALICIOUS"] + ph["SUSPICIOUS"], 4)
    out["legitimate_flagged_malicious_or_suspicious"] = round(lg["MALICIOUS"] + lg["SUSPICIOUS"], 4)
    out["legitimate_marked_safe"] = lg["SAFE"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2500, help="URLs per class from the test split")
    ap.add_argument("--old", help="path to a RAQEEB 2.1 checkout for the before/after comparison")
    a = ap.parse_args()
    from train_sawnn import sample_and_split
    _, _, _, _, test = sample_and_split()
    rng = np.random.RandomState(7)
    sel = np.concatenate([rng.choice(np.where(test.label.values == c)[0], a.n, replace=False) for c in (1, 0)])
    sub = test.iloc[sel]
    urls = ["http://" + u for u in sub.url]
    labels = sub.label.tolist()
    res = {"test_split": "domain-grouped held-out test split from train_sawnn.py (no registered domain seen in training)",
           "n_per_class": a.n, "threat_feeds": "off (see module docstring)", "mode": "quick scan (link analysis only)"}
    t0 = time.time()
    res["mira"] = table(run(ROOT, urls, "mira"), labels)
    res["mira"]["seconds"] = round(time.time() - t0, 1)
    if a.old:
        t0 = time.time()
        res["raqeeb_2_1"] = table(run(Path(a.old), urls, "old"), labels)
        res["raqeeb_2_1"]["seconds"] = round(time.time() - t0, 1)
    import pandas as pd
    ue = pd.read_csv(ROOT / "data" / "uae_eval.csv")
    res["uae_eval_mira"] = table(run(ROOT, ue.url.tolist(), "uae"), ue.label.tolist())
    if a.old:
        res["uae_eval_raqeeb_2_1"] = table(run(Path(a.old), ue.url.tolist(), "uae_old"), ue.label.tolist())
    (ROOT / "models" / "evaluation_verdicts.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
