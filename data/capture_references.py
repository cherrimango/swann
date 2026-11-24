"""Capture reference screenshots of official websites for visual impersonation checks.

Only domains marked verified in the registry are captured. Files go to data/references/<brand_id>/<domain>.png.
Needs internet and Playwright (pip install playwright && python -m playwright install chromium).

    python data/capture_references.py                 # every verified domain
    python data/capture_references.py --brand uaepass # one organisation
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from raqeeb.link.official_domains import organisations  # noqa: E402
from raqeeb.link.sandbox import UA  # noqa: E402
from raqeeb.link.visual import REFS  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--brand")
    a = ap.parse_args()
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch()
        pg = b.new_page(user_agent=UA, viewport={"width": 390, "height": 844})
        for o in organisations():
            if a.brand and o["id"] != a.brand:
                continue
            for d in o["domains"]:
                if d["status"] != "verified":
                    continue
                out = REFS / o["id"] / f"{d['domain']}.png"
                out.parent.mkdir(parents=True, exist_ok=True)
                try:
                    pg.goto(f"https://{d['domain']}/", timeout=20000, wait_until="domcontentloaded")
                    pg.wait_for_timeout(1500)
                    pg.screenshot(path=str(out))
                    print("saved", out)
                except Exception as e:  # noqa: BLE001
                    print("skipped", d["domain"], str(e).splitlines()[0][:100])
        b.close()


if __name__ == "__main__":
    main()
