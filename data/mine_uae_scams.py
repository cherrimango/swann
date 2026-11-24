"""Mine public phishing feeds for URLs that impersonate UAE brands -> data/uae_scam_urls.csv.

    python data/mine_uae_scams.py   (run from the repo root after data/download.py)
"""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import re, csv, collections
from raqeeb.brands import BRANDS, detect, collapse
from raqeeb.urlparse import parse
kws=set()
for b in BRANDS:
    for k in b["keywords"]:
        k=k.replace("-","")
        if len(k)>=4: kws.add(k); kws.add(collapse(k))
rx=re.compile("|".join(sorted(map(re.escape,kws),key=len,reverse=True)))
rows=[]; seen=set()
for f,src in [("data/raw/openphish.txt","OpenPhish"),("data/raw/phishdb_links.txt","Phishing.Database")]:
    for line in open(f,encoding="utf-8",errors="ignore"):
        u=line.strip()
        if not u.lower().startswith(("http://","https://")): continue
        low=u.lower().replace("-","")
        if not (rx.search(low) or rx.search(collapse(low)) or "xn--" in low): continue
        if u in seen: continue
        seen.add(u)
        p=parse(u); hits=detect(p)
        if not hits: continue
        h=hits[0]
        if h.kind in("weak_token",) or h.strength<0.8: continue
        rows.append([u,p.host,p.registered_domain,h.brand_id,h.brand_name,h.kind,h.matched,src])
print(len(rows))
c=collections.Counter(r[4] for r in rows); print(c.most_common(40))
k=collections.Counter(r[5] for r in rows); print(k)
with open("data/uae_scam_urls.csv","w",newline="",encoding="utf-8") as fh:
    w=csv.writer(fh); w.writerow(["url","host","registered_domain","brand_id","brand","match","matched","source"]); w.writerows(rows)
