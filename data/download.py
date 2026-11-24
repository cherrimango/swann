"""Download training data and rebuild the threat-intel lists.

    python data/download.py                 # phishing feeds + top-1M legit domains + threat lists
    python data/download.py --phiusiil      # also PhiUSIIL full-URL dataset (UCI, needs `pip install ucimlrepo`)
    python data/download.py --phreshphish   # also PhreshPhish URLs (Hugging Face, needs `pip install datasets`)

Run it again right before the evaluation so the threat lists are fresh.
"""
import argparse
import gzip
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from raqeeb.urlparse import FREE_HOSTING, parse  # noqa: E402

RAW = ROOT / "data" / "raw"
SOURCES = {
    "openphish.txt": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
    "phishdb_links.txt": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "top1m.txt": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains",
}


def fetch(name, url):
    dest = RAW / name
    print(f"downloading {name} ...")
    urllib.request.urlretrieve(url, dest)
    print(f"  {sum(1 for _ in dest.open(encoding='utf-8', errors='ignore'))} lines")


def build_threat_lists():
    top = set((ROOT / "raqeeb" / "data" / "top_legit_10k.txt").read_text().split())
    hosts, urls = set(), set()
    for name in ("openphish.txt", "phishdb_links.txt"):
        path = RAW / name
        if not path.exists():
            continue
        for line in path.open(encoding="utf-8", errors="ignore"):
            line = line.strip()
            if not line.lower().startswith(("http://", "https://")):
                continue
            p = parse(line)
            if not p.host:
                continue
            if p.registered_domain in top or p.host in FREE_HOSTING:
                urls.add(p.url.lower().rstrip("/"))  # shared platforms: exact URL only
            else:
                hosts.add(p.host.removeprefix("www."))
    out = ROOT / "models"
    out.mkdir(exist_ok=True)
    with gzip.open(out / "threat_hosts.txt.gz", "wt") as g:
        g.write("\n".join(sorted(hosts)))
    with gzip.open(out / "threat_urls.txt.gz", "wt") as g:
        g.write("\n".join(sorted(urls)))
    print(f"threat lists: {len(hosts)} hosts, {len(urls)} exact URLs")


def phiusiil():
    from ucimlrepo import fetch_ucirepo
    ds = fetch_ucirepo(id=967)
    df = ds.data.features[["URL"]].copy()
    df["label"] = 1 - ds.data.targets.iloc[:, 0].astype(int)  # PhiUSIIL: 1 = legitimate -> flip to 1 = phishing
    df.rename(columns={"URL": "url"}).to_csv(RAW / "phiusiil_urls.csv", index=False)
    print(f"PhiUSIIL: {len(df)} rows -> data/raw/phiusiil_urls.csv")


def phreshphish():
    from datasets import load_dataset
    ds = load_dataset("phreshphish/phreshphish", split="train", columns=["url", "label"])
    df = ds.to_pandas()
    df["label"] = (df["label"].str.lower() == "phish").astype(int)
    df.to_csv(RAW / "phreshphish_urls.csv", index=False)
    print(f"PhreshPhish: {len(df)} rows -> data/raw/phreshphish_urls.csv")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phiusiil", action="store_true")
    ap.add_argument("--phreshphish", action="store_true")
    ap.add_argument("--skip-feeds", action="store_true")
    a = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    if not a.skip_feeds:
        for n, u in SOURCES.items():
            fetch(n, u)
    build_threat_lists()
    if a.phiusiil:
        phiusiil()
    if a.phreshphish:
        phreshphish()
