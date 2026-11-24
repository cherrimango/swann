"""Early detection: find UAE-brand look-alike domains BEFORE victims report them.

    python hunter.py permute --brand tamm            # generate look-alikes, keep the ones that are registered (DNS)
    python hunter.py crtsh --days 7                  # new TLS certificates whose names contain UAE brand keywords
    python hunter.py stream                          # live Certificate Transparency stream (pip install certstream)

Every candidate is scored by the RAQEEB engine and written to hunt_results.csv.
"""
import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor

from raqeeb.brands import BRANDS
from raqeeb.engine import scan_many
from raqeeb.hunt import candidates, crtsh, keywords_for, resolves, stream


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["permute", "crtsh", "stream"])
    ap.add_argument("--brand", action="append", help="brand id from brands.json (repeatable); default all")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--max-per-brand", type=int, default=3000)
    ap.add_argument("--no-dns", action="store_true", help="skip DNS check (score every generated candidate)")
    ap.add_argument("-o", "--output", default="hunt_results.csv")
    a = ap.parse_args()

    f = open(a.output, "w", newline="", encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["domain", "source", "ip", "risk_score", "verdict", "brand", "top_reason"])
    if a.mode == "stream":
        stream(keywords_for(a.brand), w)
        return

    if a.mode == "permute":
        doms = []
        for b in BRANDS:
            if not a.brand or b["id"] in a.brand:
                doms += candidates(b, a.max_per_brand)
        print(f"{len(doms)} candidate look-alike domains", file=sys.stderr)
        if a.no_dns:
            live = [(d, "") for d in doms]
        else:
            with ThreadPoolExecutor(64) as ex:
                ips = list(ex.map(resolves, doms))
            live = [(d, ip) for d, ip in zip(doms, ips) if ip]
            print(f"{len(live)} are registered and resolving", file=sys.stderr)
        source = "permutation"
    else:
        names = crtsh(a.days, keywords_for(a.brand))
        live = [(d, "") for d in names]
        source = f"crt.sh (last {a.days}d)"
        print(f"{len(names)} new certificate names match UAE brand keywords", file=sys.stderr)

    results = scan_many([d for d, _ in live]) if live else []
    for (d, ip), r in sorted(zip(live, results), key=lambda x: -x[1]["risk_score"]):
        w.writerow([d, source, ip, r["risk_score"], r["verdict"], (r["impersonated_brand"] or {}).get("name", ""),
                    r["reasons"][0]["en"] if r["reasons"] else ""])
    f.close()
    print(f"wrote {a.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
