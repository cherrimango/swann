"""Attachment analysis for SAWNN Protect: screenshots, photos, QR images, PDFs and text files.

Uploads are never executed or opened by anything that could run their content:
- The type is decided from the file's own bytes (magic numbers), not its name or the browser's claim.
- Images are decoded by Pillow with a pixel limit, re-encoded to PNG in memory, and only that copy is processed.
- PDFs are read with pypdf for text and link annotations only; JavaScript, launch actions and embedded files are
  reported as risk indicators, never run.
- Nothing is written to disk in clear text. The report stores a SHA-256 of the upload, not the file.

Pipeline: validate -> decode QR codes (OpenCV) -> OCR (Tesseract eng+ara) -> extract URLs, phone numbers, e-mail
addresses -> scan every URL with the shared SAWNN engine -> analyse the text as a message -> structured report.
"""
import hashlib
import io
import re
import secrets
import time

from .messages import check_message as analyse_message
from .messages import URL_RX

MAX_BYTES = 10 * 1024 * 1024
MAX_PIXELS = 40_000_000
PHONE_RX = re.compile(r"(?:\+|00)?971[\s-]?\d{1,2}[\s-]?\d{3}[\s-]?\d{4}|\b0\d{1,2}[\s-]?\d{3}[\s-]?\d{4}\b|\+\d{8,15}")
EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class AttachmentError(ValueError):
    pass


def sniff(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:5] == b"%PDF-":
        return "application/pdf"
    if data[:2] == b"MZ" or data[:4] in (b"\x7fELF", b"PK\x03\x04"):
        return "blocked/executable-or-archive"
    try:
        data[:4096].decode("utf-8")
        return "text/plain"
    except UnicodeDecodeError:
        return "unknown"


def _image(data: bytes):
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        im = Image.open(io.BytesIO(data))
        im.verify()
        im = Image.open(io.BytesIO(data))
        im.load()
    except Exception as e:  # noqa: BLE001
        raise AttachmentError(f"The image could not be read safely: {str(e)[:120]}") from e
    im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "PNG")  # re-encoded copy: strips metadata and anything appended to the original file
    return im


def decode_qr(im) -> dict:
    try:
        import cv2
        import numpy as np
    except ImportError:
        return {"available": False, "reason": "OpenCV not installed", "codes": []}
    arr = cv2.cvtColor(np.array(im), cv2.COLOR_RGB2BGR)
    det = cv2.QRCodeDetector()
    codes = []
    try:
        ok, texts, _, _ = det.detectAndDecodeMulti(arr)
        if ok:
            codes = [t for t in texts if t]
    except cv2.error:
        pass
    if not codes:
        t, _, _ = det.detectAndDecode(arr)
        if t:
            codes = [t]
    return {"available": True, "codes": codes[:10]}


def ocr(im) -> dict:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
    except Exception:  # noqa: BLE001
        return {"available": False, "reason": "Tesseract OCR not installed", "text": ""}
    w, h = im.size
    if max(w, h) > 2400:
        im = im.copy()
        im.thumbnail((2400, 2400))
    try:
        text = pytesseract.image_to_string(im, lang="eng+ara", timeout=25)
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"OCR failed: {str(e)[:100]}", "text": ""}
    return {"available": True, "languages": "eng+ara", "text": text.strip()[:6000]}


def _pdf(data: bytes) -> dict:
    from pypdf import PdfReader
    try:
        r = PdfReader(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001
        raise AttachmentError(f"The PDF could not be read safely: {str(e)[:120]}") from e
    if r.is_encrypted:
        return {"text": "", "links": [], "pages": None, "risk_flags": ["encrypted PDF: contents could not be inspected"]}
    text, links, flags = [], [], []
    root = r.trailer.get("/Root", {})
    raw = data[:2_000_000]
    for marker, label in ((b"/JavaScript", "contains JavaScript"), (b"/OpenAction", "runs an action when opened"),
                          (b"/Launch", "can launch external programs"), (b"/EmbeddedFile", "has embedded files"),
                          (b"/SubmitForm", "can submit form data to a server")):
        if marker in raw:
            flags.append(label)
    for i, page in enumerate(r.pages[:30]):
        try:
            text.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001
            pass
        for a in (page.get("/Annots") or [])[:200]:
            try:
                obj = a.get_object()
                uri = (obj.get("/A") or {}).get("/URI")
                if uri:
                    links.append(str(uri)[:2000])
            except Exception:  # noqa: BLE001
                continue
    _ = root
    return {"text": "\n".join(text)[:20000], "links": links[:50], "pages": len(r.pages), "risk_flags": flags}


def analyse(data: bytes, filename: str = "", declared_type: str = "") -> dict:
    t0 = time.time()
    if not data:
        raise AttachmentError("The file is empty")
    if len(data) > MAX_BYTES:
        raise AttachmentError("The file is larger than 10 MB")
    kind = sniff(data)
    if kind == "blocked/executable-or-archive":
        raise AttachmentError("Programs and archives are not accepted. Send a screenshot of the message instead.")
    if kind == "unknown":
        raise AttachmentError("This file type is not supported. Send an image, a PDF or a text file.")
    report = {"attachment_id": "ATT-" + time.strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper(),
              "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data), "detected_type": kind,
              "declared_type": declared_type or None, "filename": (filename or "")[:120], "stages": {}, "limitations": []}
    text, qr_payloads, pdf_links, risk_flags = "", [], [], []
    if kind.startswith("image/"):
        im = _image(data)
        report["image"] = {"width": im.size[0], "height": im.size[1]}
        q = decode_qr(im)
        report["qr"] = q
        report["stages"]["qr"] = "complete" if q["available"] else "unavailable"
        qr_payloads = q["codes"]
        o = ocr(im)
        report["ocr"] = {k: v for k, v in o.items()}
        report["stages"]["ocr"] = "complete" if o["available"] else "unavailable"
        if not o["available"]:
            report["limitations"].append(f"Text in the image could not be read: {o['reason']}")
        text = o.get("text", "")
    elif kind == "application/pdf":
        p = _pdf(data)
        report["pdf"] = {"pages": p["pages"], "links": p["links"], "risk_flags": p["risk_flags"]}
        report["stages"]["pdf_text"] = "complete"
        text, pdf_links, risk_flags = p["text"], p["links"], p["risk_flags"]
    else:
        text = data[:200_000].decode("utf-8", "replace")
        report["stages"]["text"] = "complete"

    urls = []
    for src in qr_payloads + pdf_links + [m.group(0).rstrip(").,;!؟،") for m in URL_RX.finditer(text)]:
        s = src.strip()
        if s and s not in urls and (s.lower().startswith(("http://", "https://", "www.")) or URL_RX.fullmatch(s)):
            urls.append(s)
    phones = sorted({re.sub(r"[\s-]", "", m.group(0)) for m in PHONE_RX.finditer(text + " " + " ".join(qr_payloads))})[:20]
    emails = sorted({m.group(0) for m in EMAIL_RX.finditer(text)})[:20]
    report["indicators"] = {"urls": urls[:20], "phone_numbers": phones, "emails": emails,
                            "qr_payloads": qr_payloads, "non_url_qr_payloads": [q for q in qr_payloads if q not in urls]}

    from .link import pipeline
    scans = []
    for u in urls[:10]:
        try:
            r = pipeline.analyse(u, "quick")
            pipeline.save(r, None)
            scans.append({"url": u, "scan_id": r["scan_id"], "verdict": r["verdict"], "risk_score": r["risk_score"],
                          "from_qr": u in qr_payloads, "detected_brand": r.get("detected_brand"),
                          "explanation": r["explanation"], "recommended_action": r["recommended_action"]})
        except Exception as e:  # noqa: BLE001
            scans.append({"url": u, "verdict": "INCONCLUSIVE", "error": str(e)[:120]})
    report["link_scans"] = scans
    msg = analyse_message(text[:4000]) if text.strip() else None
    if msg:
        report["message_analysis"] = {"verdict": msg["verdict"], "risk_score": msg["risk_score"],
                                      "script_signals": msg["script_signals"], "brands_named": msg["brands_named"],
                                      "advice_en": msg["advice_en"], "advice_ar": msg["advice_ar"]}
    order = {"MALICIOUS": 3, "SUSPICIOUS": 2, "INCONCLUSIVE": 1, "SAFE": 0}
    worst = max((s["verdict"] for s in scans), key=lambda v: order.get(v, 1), default=None)
    mv = {"scam": "MALICIOUS", "suspicious": "SUSPICIOUS", "inconclusive": "INCONCLUSIVE", "looks safe": "SAFE"}.get((msg or {}).get("verdict"))
    cands = [v for v in (worst, mv) if v]
    if risk_flags:
        cands.append("SUSPICIOUS")
    verdict = max(cands, key=lambda v: order[v]) if cands else "INCONCLUSIVE"
    if verdict == "SAFE" and not scans:
        verdict = "INCONCLUSIVE"  # no links and no scam wording is not proof the attachment is safe
    report["verdict"] = verdict
    reasons, reasons_ar = [], []
    for s in scans:
        if s["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            reasons.append(("QR code" if s["from_qr"] else "Link") + f" {s['url'][:80]}: {s['explanation']['en']}")
            reasons_ar.append(("رمز QR" if s["from_qr"] else "الرابط") + f" {s['url'][:80]}: {s['explanation']['ar']}")
    for sig in (msg or {}).get("script_signals", []):
        reasons.append(sig["en"])
        reasons_ar.append(sig.get("ar") or sig["en"])
    reasons += [f"PDF {f}" for f in risk_flags]
    reasons_ar += [f"ملف PDF: {f}" for f in risk_flags]
    report["reasons"], report["reasons_ar"] = reasons[:8], reasons_ar[:8]
    if not urls and not text.strip():
        report["limitations"].append("No text, links or QR codes were found in this file.")
    report["duration_seconds"] = round(time.time() - t0, 2)
    return report
