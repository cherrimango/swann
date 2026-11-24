"""Build SAWNN's versioned training dataset from every available source, with provenance on every row.

Sources (place the raw files in data/raw/; data/download.py fetches the public feeds):
  url_dataset.csv     attached labelled URL dataset (url,type = legitimate|phishing), 450,176 rows
  phishdb_links.txt   Phishing.Database active phishing links
  openphish.txt       OpenPhish community feed (newest snapshot; kept out of training as a fresh-threat test set)
  top1m.txt           top-1M popular domains (legitimate class, hostnames only)

Steps: normalise -> drop invalid -> deduplicate on the normalised URL -> drop URLs labelled both ways -> balance the
legitimate hostname-only rows with phishing hostname-only rows (so "has no path" cannot become a shortcut) -> record
source and label per row -> write data/processed/<version>.csv.gz and a manifest.

Known artefact handled here: in url_dataset.csv every legitimate URL starts with "https://www." while only ~6% of the
phishing URLs use HTTPS. The scheme and a leading "www." are therefore stripped before features are computed, so the
model cannot learn "HTTPS means safe".

    python data/build_dataset.py
"""
import gzip
import hashlib
import json
import random
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from raqeeb.urlparse import parse  # noqa: E402

RAW, OUT = ROOT / "data" / "raw", ROOT / "data" / "processed"
SEED = 42


def norm(u: str) -> str | None:
    """Canonical form used for dedup, features and splits: no scheme, no leading www., lower-case host."""
    u = (u or "").strip().strip('"').replace("&amp;", "&")
    if not u or " " in u.strip():
        return None
    p = parse(u)
    if not p.host or ("." not in p.host and not p.is_ip):
        return None
    host = p.host.removeprefix("www.")
    path = re.sub(r"/{2,}", "/", p.path or "")
    q = ("?" + p.query) if p.query else ""
    out = host + (path if path not in ("", "/") else "") + q
    return out[:2000]


def lines(f):
    return [l.strip() for l in f.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")] if f.exists() else []


def main():
    t0 = time.time()
    rng = random.Random(SEED)
    rows, stats = [], {}

    att = RAW / "url_dataset.csv"
    if att.exists():
        d = pd.read_csv(att)
        d["label"] = (d["type"].str.lower() == "phishing").astype(int)
        for u, y in zip(d["url"], d["label"]):
            rows.append((u, y, "url_dataset.csv"))
        stats["url_dataset.csv"] = {"raw_rows": len(d), "phishing": int(d.label.sum()), "legitimate": int((d.label == 0).sum())}

    ph = [u for u in lines(RAW / "phishdb_links.txt") if u.lower().startswith(("http://", "https://"))]
    stats["phishdb_links.txt"] = {"raw_rows": len(ph)}
    rows += [(u, 1, "Phishing.Database") for u in ph]

    top = lines(RAW / "top1m.txt") or lines(RAW / "top100k.txt")
    stats["top1m.txt"] = {"raw_rows": len(top)}

    df = pd.DataFrame(rows, columns=["raw", "label", "source"])
    df["url"] = [norm(u) for u in df.raw]
    invalid = int(df.url.isna().sum())
    df = df.dropna(subset=["url"])
    conflicts = df.groupby("url").label.nunique()
    conflict_urls = set(conflicts[conflicts > 1].index)
    df = df[~df.url.isin(conflict_urls)].drop_duplicates("url")

    # legitimate hostname-only rows from the popular-domain list, matched by phishing hostname-only rows
    phish_regs = {parse("http://" + u).registered_domain for u in df[df.label == 1].url}
    have = set(df.url)
    legit_hosts = [d for d in top if d not in phish_regs and d not in have]
    rng.shuffle(legit_hosts)
    phish_hosts = sorted({parse("http://" + u).host for u in df[df.label == 1].url} - have)
    rng.shuffle(phish_hosts)
    n = min(len(phish_hosts), 150_000, len(legit_hosts))
    extra = pd.DataFrame({"url": legit_hosts[:n] + phish_hosts[:n], "label": [0] * n + [1] * n,
                          "source": ["top1m (hostname)"] * n + ["Phishing.Database (hostname)"] * n})
    df = pd.concat([df[["url", "label", "source"]], extra], ignore_index=True).drop_duplicates("url")
    df["group"] = [parse("http://" + u).registered_domain or u for u in df.url]

    fresh = [norm(u) for u in lines(RAW / "openphish.txt")]
    fresh = sorted({u for u in fresh if u})
    version = "sawnn-ds-" + hashlib.sha256("\n".join(sorted(df.url)).encode()).hexdigest()[:10]
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{version}.csv.gz"
    df.to_csv(path, index=False, compression="gzip")
    (OUT / "openphish_fresh.txt").write_text("\n".join(fresh))
    manifest = {
        "version": version, "built": time.strftime("%Y-%m-%d %H:%M"), "file": str(path.relative_to(ROOT)),
        "rows": len(df), "phishing": int(df.label.sum()), "legitimate": int((df.label == 0).sum()),
        "registered_domains": int(df.group.nunique()), "by_source": df.groupby(["source", "label"]).size().rename("n").reset_index()
        .assign(label=lambda x: x.label.map({0: "legitimate", 1: "phishing"})).to_dict("records"),
        "sources_raw": stats, "invalid_dropped": invalid, "label_conflicts_dropped": len(conflict_urls),
        "fresh_test_set": {"file": "data/processed/openphish_fresh.txt", "rows": len(fresh), "note": "OpenPhish snapshot, kept out of training"},
        "normalisation": "scheme and leading www. removed; host lower-cased; repeated slashes collapsed; fragment dropped",
        "known_artefacts": ["url_dataset.csv legitimate rows all use https://www. (phishing rows ~6% HTTPS): scheme removed before features",
                            "popular-domain list is not a verified benign set: popularity is not safety"],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ("version", "rows", "phishing", "legitimate", "registered_domains", "invalid_dropped",
                                               "label_conflicts_dropped")}, indent=2), f"\n{time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
