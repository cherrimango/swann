"""Server-side safety: SSRF-safe fetching, upload validation + encrypted evidence storage, rate limiting."""
import base64
import hashlib
import io
import ipaddress
import os
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
from cryptography.fernet import Fernet

from .db import ROOT

KEYS = ROOT / "data" / "keys"
UPLOADS = ROOT / "evidence" / "uploads"
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_FETCH = 2_000_000
MAX_UPLOAD = 5 * 1024 * 1024


# ---------- SSRF-safe fetching ----------
class UnsafeTarget(Exception):
    pass


def _check_host(host: str, port: int):
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeTarget(f"cannot resolve {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise UnsafeTarget(f"{host} resolves to a non-public address")


def check_url(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTarget("only public http(s) URLs can be inspected")
    _check_host(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))


def safe_get(url: str, headers=None, timeout=8, max_redirects=6):
    """GET that refuses internal targets on every redirect hop and caps the body size.
    Returns (response, chain, body_text)."""
    chain = []
    cur = url
    for _ in range(max_redirects + 1):
        check_url(cur)
        r = requests.get(cur, headers=headers or {}, timeout=timeout, allow_redirects=False, stream=True)
        chain.append({"status": r.status_code, "url": cur})
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location")
            r.close()
            if not loc:
                break
            cur = urljoin(cur, loc)
            continue
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) > MAX_FETCH:
                break
        r.close()
        r.url = cur  # final URL after our own redirect handling
        enc = r.encoding or "utf-8"
        return r, chain, body.decode(enc, "replace")
    raise UnsafeTarget("too many redirects")


# ---------- uploads ----------
def _fernet() -> Fernet:
    KEYS.mkdir(parents=True, exist_ok=True)
    f = KEYS / "evidence.key"
    key = os.environ.get("RAQEEB_EVIDENCE_KEY", "").encode() or (f.read_bytes() if f.exists() else b"")
    if not key:
        key = Fernet.generate_key()
        f.write_bytes(key)
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    return Fernet(key)


class BadUpload(Exception):
    pass


def store_image(data: bytes) -> dict:
    """Validate an uploaded screenshot, re-encode it (drops metadata and any trailing payload), encrypt at rest."""
    from PIL import Image, UnidentifiedImageError
    if not data or len(data) > MAX_UPLOAD:
        raise BadUpload("Images must be under 5 MB")
    try:
        with Image.open(io.BytesIO(data)) as probe:
            fmt = probe.format
            probe.verify()
        if fmt not in ("PNG", "JPEG", "WEBP"):
            raise BadUpload("Send a PNG, JPEG or WebP image")
        with Image.open(io.BytesIO(data)) as img:
            if img.width * img.height > 40_000_000:
                raise BadUpload("Image is too large")
            img = img.convert("RGB")
            img.thumbnail((2400, 2400))
            out = io.BytesIO()
            img.save(out, "PNG")
    except (UnidentifiedImageError, OSError, SyntaxError) as e:
        raise BadUpload("That file isn’t a readable image") from e
    clean = out.getvalue()
    UPLOADS.mkdir(parents=True, exist_ok=True)
    name = secrets.token_hex(12)
    (UPLOADS / f"{name}.bin").write_bytes(_fernet().encrypt(clean))
    return {"id": name, "sha256": hashlib.sha256(clean).hexdigest(), "bytes": len(clean)}


def read_image(upload_id: str) -> bytes:
    if not upload_id.isalnum():
        raise BadUpload("bad id")
    return _fernet().decrypt((UPLOADS / f"{upload_id}.bin").read_bytes())


def ocr_image(upload_id: str) -> str:
    """Development adapter: OCR runs only if Tesseract is installed (pip install pytesseract + the tesseract binary)."""
    try:
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(io.BytesIO(read_image(upload_id))), lang="eng+ara")[:4000]
    except Exception:  # noqa: BLE001
        return ""


# ---------- rate limiting ----------
class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self.lock:
            self.hits.clear()


limiter = RateLimiter()

LIMITS = {
    "login": (8, 300),
    "register": (5, 3600),
    "report": (12, 600),
    "corroborate": (40, 3600),
    "check": (180, 60),
    "upload": (20, 600),
}


def ip_hash(ip: str) -> str:
    salt = (KEYS / "evidence.key").read_bytes()[:16] if (KEYS / "evidence.key").exists() else b"raqeeb"
    return hashlib.sha256(salt + ip.encode()).hexdigest()[:16]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()
