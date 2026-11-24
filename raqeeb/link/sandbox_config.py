"""MIRA sandbox configuration and analysis parameters (Command page "Sandbox Configuration & Analysis Parameters").

CONFIG describes how the sandbox is actually set up, read from the same constants and environment the sandbox uses,
so the page cannot drift from the code. collected(report) says, for one scan, which parameters were really collected.
"""
import os
import shutil

from . import redirects, sandbox


def _docker_available() -> bool:
    return bool(shutil.which("docker")) and os.path.exists("/var/run/docker.sock")


def config() -> dict:
    exe = os.environ.get("MIRA_CHROMIUM")
    try:
        import playwright  # noqa: F401
        pw = True
    except ImportError:
        pw = False
    enabled = os.environ.get("MIRA_SANDBOX_ENABLED", "1") not in ("0", "false", "no")
    timeout_ms = int(os.environ.get("MIRA_SANDBOX_TIMEOUT", sandbox.NAV_TIMEOUT_MS))
    groups = [
        ("Navigation", [
            ("Navigation timeout", f"{timeout_ms / 1000:.0f} s", "MIRA_SANDBOX_TIMEOUT"),
            ("Wait for load state", "DOMContentLoaded, then 1.5 s for client-side redirects and scripts", None),
            ("Maximum redirect hops analysed", str(redirects.MAX_HOPS), None),
            ("Redirect types recorded", "HTTP 301/302/303/307/308 and client-side (JavaScript / meta refresh)", None),
        ]),
        ("Browser", [
            ("Engine", "Chromium via Playwright" if pw else "Playwright not installed: static HTTP fetch fallback", None),
            ("Executable", exe or "Playwright's bundled Chromium", "MIRA_CHROMIUM"),
            ("User agent", sandbox.UA, None),
            ("Viewport", "390 × 844 (mobile, as most scam links arrive on phones)", None),
            ("JavaScript", "enabled", None),
            ("Service workers", "blocked", None),
            ("Dialogs (alert/confirm/prompt)", "dismissed automatically", None),
            ("TLS errors", "ignored for loading so the page can be inspected; the certificate is validated separately", None),
        ]),
        ("Network and security", [
            ("SSRF guard", "every request, including each redirect hop and sub-resource, is resolved and blocked if it points "
                           "to loopback, private, link-local, multicast, reserved or cloud-metadata addresses", None),
            ("Downloads", "refused; the file name is recorded as evidence", None),
            ("Uploads", "none; the sandbox never submits forms or types data", None),
            ("Isolation", "hardened Docker container available" if _docker_available() else
             "process-level isolation on the MIRA server (no Docker daemon available here); see infrastructure/sandbox for the "
             "container profile intended for production", None),
            ("Enabled", "yes" if enabled else "no", "MIRA_SANDBOX_ENABLED"),
        ]),
        ("Page content collected", [
            ("Title, meta description, visible text", "first 5,000 characters of visible text", None),
            ("Forms", "action, method, whether data is sent to another site", None),
            ("Input fields", "counts of password, email, telephone and payment fields; hidden inputs", None),
            ("Links and third-party domains", "external link count, up to 40 third-party domains", None),
            ("Scripts and iframes", "counts", None),
            ("Logo references", "image sources or alt text mentioning a logo or brand", None),
        ]),
        ("Visual and evidence", [
            ("Screenshot", "viewport PNG, stored under evidence/scans/<scan_id>.png", None),
            ("OCR", "Tesseract, English + Arabic, when installed", None),
            ("Visual comparison", "perceptual hash, edge layout and colour histogram against verified official references", None),
        ]),
        ("TLS and domain", [
            ("Certificate", "issuer, validity, SANs, fingerprint, hostname match", None),
            ("Registration", "RDAP creation date and registrar", None),
            ("DNS", "A/AAAA/MX/NS/TXT records, NXDOMAIN", None),
        ]),
    ]
    return {"enabled": enabled, "engine_available": pw, "groups": [
        {"name": g, "parameters": [{"name": n, "value": v, "env": e} for n, v, e in items]} for g, items in groups]}


PARAMS = [
    ("final_url", "Final URL"), ("http_status", "HTTP status"), ("redirect_chain", "Redirect chain"),
    ("page_title", "Page title"), ("visible_text", "Visible text"), ("forms", "Forms"), ("password_fields", "Password fields"),
    ("payment_fields", "Payment fields"), ("third_party_domains", "Third-party domains"), ("scripts", "Scripts"),
    ("iframes", "Iframes"), ("downloads_blocked", "Blocked downloads"), ("blocked_internal_requests", "Blocked internal requests"),
    ("screenshot", "Screenshot"), ("logo_references", "Logo references"),
]


def collected(report: dict) -> dict:
    sb = report.get("website_analysis") or {}
    vis = report.get("visual_analysis") or {}
    dom = report.get("domain_intelligence") or {}
    rows = [{"parameter": label, "collected": bool(sb.get("available")) and sb.get(key) not in (None, False, "")} for key, label in PARAMS]
    rows += [{"parameter": "OCR text", "collected": bool((vis.get("ocr") or {}).get("available"))},
             {"parameter": "Visual similarity", "collected": bool(vis.get("available"))},
             {"parameter": "Certificate", "collected": bool((dom.get("certificate") or {}).get("available"))},
             {"parameter": "Registration (RDAP)", "collected": bool((dom.get("rdap") or {}).get("available"))},
             {"parameter": "DNS", "collected": bool((dom.get("dns") or {}).get("available"))}]
    return {"scan_id": report.get("scan_id"), "mode": report.get("mode"), "sandbox_mode": sb.get("mode"),
            "sandbox_error": None if sb.get("available") else (sb.get("error") or sb.get("reason")),
            "parameters": rows, "collected": sum(r["collected"] for r in rows), "total": len(rows)}
