"""Visual impersonation analysis: compares a page screenshot with verified reference screenshots of official sites.

Methods (all scores 0-1):
  perceptual_similarity - DCT perceptual hash (pHash) distance
  layout_similarity     - correlation of downscaled edge maps
  colour_similarity     - colour-histogram intersection
  ocr_brand_text        - brand names read from the screenshot (Tesseract, English + Arabic) when installed
References live in data/references/<brand_id>/*.png (capture them with data/capture_references.py from the official
domains in the registry). Without references the visual comparison is reported as unavailable, never as "no match".
A high visual similarity alone does not prove fraud: the risk engine only uses it together with a domain mismatch.
"""
from pathlib import Path

import numpy as np

from ..brands import BRANDS
from ..db import ROOT

REFS = ROOT / "data" / "references"


def _gray(img, size):
    return np.asarray(img.convert("L").resize(size), dtype=np.float32)


def _dct2(a):
    n = a.shape[0]
    k = np.arange(n)
    basis = np.cos(np.pi * (2 * k[None, :] + 1) * k[:, None] / (2 * n))
    return basis @ a @ basis.T


def phash(img) -> np.ndarray:
    d = _dct2(_gray(img, (32, 32)))[:8, :8].flatten()
    return d[1:] > np.median(d[1:])


def edge_map(img) -> np.ndarray:
    g = _gray(img, (96, 160))
    e = np.abs(np.diff(g, axis=0))[:, :-1] + np.abs(np.diff(g, axis=1))[:-1, :]
    return (e - e.mean()) / (e.std() + 1e-6)


def colour_hist(img) -> np.ndarray:
    a = np.asarray(img.convert("RGB").resize((128, 128))) // 32
    h = np.bincount((a[..., 0] * 64 + a[..., 1] * 8 + a[..., 2]).ravel(), minlength=512).astype(np.float32)
    return h / h.sum()


def compare(img, ref) -> dict:
    p = 1 - np.count_nonzero(phash(img) != phash(ref)) / 63
    layout = float(np.clip((edge_map(img) * edge_map(ref)).mean(), 0, 1))
    colour = float(np.minimum(colour_hist(img), colour_hist(ref)).sum())
    return {"perceptual_similarity": round(float(p), 3), "layout_similarity": round(layout, 3), "colour_similarity": round(colour, 3),
            "overall": round(0.45 * p + 0.35 * layout + 0.2 * colour, 3)}


def ocr(img) -> dict:
    try:
        import pytesseract
        langs = [lang for lang in ("eng", "ara") if lang in pytesseract.get_languages()]
        return {"available": True, "text": pytesseract.image_to_string(img, lang="+".join(langs) or "eng")[:3000]}
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": f"OCR unavailable: {str(e)[:120]}"}


def brands_in_text(text: str) -> list[str]:
    low = (text or "").lower()
    found = []
    for b in BRANDS:
        terms = [t for t in b["content_terms"] if len(t) >= 4]
        if any((t.lower() in low) if t.isascii() else (t in text) for t in terms):
            found.append(b["name"])
    return found[:5]


def references() -> dict[str, list[Path]]:
    if not REFS.exists():
        return {}
    return {d.name: sorted(d.glob("*.png")) for d in REFS.iterdir() if d.is_dir() and any(d.glob("*.png"))}


def analyse(screenshot: Path | None, page_text: str = "") -> dict:
    out = {"available": False, "screenshot_reference": None, "detected_brand": None, "ocr": {"available": False},
           "brand_text_found": brands_in_text(page_text), "perceptual_similarity": None, "layout_similarity": None,
           "logo_similarity": None, "embedding_similarity": None, "overall_visual_similarity": None, "indicators": []}
    if not screenshot or not Path(screenshot).exists():
        out["reason"] = "No screenshot: the browser sandbox did not capture the page"
        return out
    from PIL import Image
    img = Image.open(screenshot)
    out["screenshot_reference"] = Path(screenshot).name
    out["ocr"] = ocr(img)
    if out["ocr"].get("available"):
        out["brand_text_found"] = sorted(set(out["brand_text_found"]) | set(brands_in_text(out["ocr"]["text"])))
    refs = references()
    if not refs:
        out["reason"] = "No verified reference screenshots installed (run data/capture_references.py)"
        out["logo_similarity_note"] = out["embedding_note"] = "not implemented in this build"
        return out
    best = None
    for brand_id, files in refs.items():
        for f in files:
            s = compare(img, Image.open(f))
            if not best or s["overall"] > best[1]["overall"]:
                best = (brand_id, s, f.name)
    name = next((b["name"] for b in BRANDS if b["id"] == best[0]), best[0])
    out.update({"available": True, "detected_brand": name if best[1]["overall"] >= 0.6 else None, "closest_reference": f"{best[0]}/{best[2]}",
                "perceptual_similarity": best[1]["perceptual_similarity"], "layout_similarity": best[1]["layout_similarity"],
                "colour_similarity": best[1]["colour_similarity"], "overall_visual_similarity": best[1]["overall"],
                "logo_similarity_note": "not implemented in this build", "embedding_note": "not implemented in this build"})
    if best[1]["overall"] >= 0.6:
        out["indicators"].append(f"Looks like the official {name} page (visual similarity {best[1]['overall']:.2f})")
    return out
