"""Score URLs from a file or the command line.

    python predict.py urls.csv            -> predictions.csv (url,label,verdict,risk_score,brand,reasons)
    python predict.py urls.txt -o out.csv
    python predict.py --url "http://tamm-fines-pay.top/login"
    python predict.py urls.csv --live     -> also unroll redirects, check domain age, page content, cloaking
"""
import argparse
import csv
import json
import sys
from pathlib import Path

from raqeeb.engine import scan_many


def read_urls(path: Path) -> list[str]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            col = next((c for c in reader.fieldnames or [] if c.strip().lower() in ("url", "urls", "link", "domain")), None)
            if col is None:
                raise SystemExit(f"No url column found in {path}: {reader.fieldnames}")
            return [row[col].strip() for row in reader if row.get(col, "").strip()]
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", help="CSV with a 'url' column, or a text file with one URL per line")
    ap.add_argument("--url", help="score a single URL and print JSON")
    ap.add_argument("-o", "--output", default="predictions.csv")
    ap.add_argument("--live", action="store_true", help="enrich with network checks (needs internet)")
    ap.add_argument("--evidence-dir", default="evidence", help="where --live writes evidence packs for flagged URLs")
    ap.add_argument("--batch", type=int, default=5000)
    a = ap.parse_args()

    if a.url:
        res = scan_many([a.url])
        if a.live:
            from raqeeb.live import enrich
            res = [enrich(r, Path(a.evidence_dir)) for r in res]
        print(json.dumps(res[0], ensure_ascii=False, indent=2))
        return
    if not a.input:
        ap.error("give an input file or --url")

    urls = read_urls(Path(a.input))
    results = []
    for i in range(0, len(urls), a.batch):
        results += scan_many(urls[i:i + a.batch])
        print(f"scored {min(i + a.batch, len(urls))}/{len(urls)}", file=sys.stderr)
    if a.live:
        from raqeeb.live import enrich
        results = [enrich(r, Path(a.evidence_dir)) for r in results]

    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "verdict", "risk_score", "impersonated_brand", "reasons_en", "reasons_ar"])
        for r in results:
            b = r["impersonated_brand"]["name"] if r["impersonated_brand"] else ""
            w.writerow([r["url"], r["label"], r["verdict"], r["risk_score"], b,
                        " | ".join(x["en"] for x in r["reasons"]), " | ".join(x["ar"] for x in r["reasons"])])
    flagged = sum(r["label"] for r in results)
    print(f"wrote {a.output}: {len(results)} URLs, {flagged} flagged as phishing", file=sys.stderr)


if __name__ == "__main__":
    main()
