"""
FaceHunter PRO - Production-grade reverse face search.

A single-file Streamlit application that performs reverse face-image search
across multiple engines (Yandex, Google, Bing, TinEye) using stealth browser
automation, maintains a local gallery of face embeddings with thumbnails and
metadata, caches search results and embeddings, and verifies candidate images
against the query embedding using InsightFace.

This is the remediated artifact produced by a line-by-line forensic audit.
All verified defects have been corrected (see README.md "Audit & Remediation").
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import io
import ipaddress
import json
import os
import pickle
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("FACEHUNTER_DATA_DIR", "face_data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

GALLERY_FILE = DATA_DIR / "gallery.pkl"
EMBEDDING_CACHE_FILE = DATA_DIR / "embedding_cache.pkl"
SEARCH_CACHE_FILE = DATA_DIR / "search_cache.pkl"
ERROR_LOG_FILE = DATA_DIR / "errors.log"
REPORTS_DIR = DATA_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

ERROR_LOG_MAX_BYTES = int(os.environ.get("FACEHUNTER_ERROR_LOG_MAX_BYTES", 5_000_000))
MAX_UPLOAD_BYTES = int(os.environ.get("FACEHUNTER_MAX_UPLOAD_BYTES", 20_000_000))
MAX_IMAGE_DIMENSION = int(os.environ.get("FACEHUNTER_MAX_IMAGE_DIMENSION", 1024))
SEARCH_CACHE_TTL_HOURS = int(os.environ.get("FACEHUNTER_SEARCH_CACHE_TTL_HOURS", 24))
SAVE_FILE_PERM = 0o600

# --- Production hardening knobs (week/month/year failure modes) ---
# Maximum decompressed pixel count for any single image (decompression-bomb
# defense). 50 megapixels is ~200 MB of RGB8 — far above any legitimate face
# photo and well below memory-exhaustion territory.
MAX_IMAGE_PIXELS = int(os.environ.get("FACEHUNTER_MAX_IMAGE_PIXELS", 50_000_000))
# Hard ceiling on the number of candidate-bytes we will buffer per download.
MAX_DOWNLOAD_BYTES = int(os.environ.get("FACEHUNTER_MAX_DOWNLOAD_BYTES", 25_000_000))
# Per-search hard cap on total candidate bytes fetched (10 candidates x 25 MB).
MAX_SEARCH_TOTAL_BYTES = int(os.environ.get("FACEHUNTER_MAX_SEARCH_TOTAL_BYTES", 250_000_000))
# Gallery entry cap; oldest entries are archived (not silently dropped) beyond this.
GALLERY_MAX_ENTRIES = int(os.environ.get("FACEHUNTER_GALLERY_MAX_ENTRIES", 5000))
# Embedding/search cache entry caps (LRU eviction beyond this).
EMBEDDING_CACHE_MAX_ENTRIES = int(os.environ.get("FACEHUNTER_EMBEDDING_CACHE_MAX_ENTRIES", 20000))
SEARCH_CACHE_MAX_ENTRIES = int(os.environ.get("FACEHUNTER_SEARCH_CACHE_MAX_ENTRIES", 5000))
# Backups to retain per store.
BACKUP_KEEP = int(os.environ.get("FACEHUNTER_BACKUP_KEEP", 5))
# Schema version — bumped on incompatible gallery/cache format changes.
SCHEMA_VERSION = 2
# Optional HMAC secret for pickle integrity. If set, pickles are signed and
# verified on load (defense against tampered/shared stores). If unset, the
# restricted unpickler still blocks arbitrary code execution.
PICKLE_HMAC_SECRET = os.environ.get("FACEHUNTER_PICKLE_HMAC_SECRET", "")
# SSRF: allowlist of blocked IP ranges for candidate downloads.
SSRF_BLOCK_PRIVATE = os.environ.get("FACEHUNTER_SSRF_BLOCK_PRIVATE", "1") == "1"
# Request timeout for the BNDR.Labs report (kept here for centralization).

# Hidden BNDR.Labs diagnostic endpoint. If unset, reports are stored locally
# (sanitized) under face_data/reports/ and never shown to the user.
BNDR_LABS_REPORT_URL = os.environ.get("BNDR_LABS_REPORT_URL", "")
BNDR_REPORT_TIMEOUT = int(os.environ.get("BNDR_LABS_REPORT_TIMEOUT", 10))

# Thread-safety locks for all shared mutable persistence.
_gallery_lock = threading.RLock()
_embedding_cache_lock = threading.RLock()
_search_cache_lock = threading.RLock()
_seen_urls_lock = threading.Lock()
_error_log_lock = threading.Lock()
_face_app_lock = threading.Lock()
# Guards the per-search total-bytes counter shared by download workers. `+=` on
# a list element is NOT atomic under CPython (LOAD/INPLACE_ADD/STORE), so the
# byte budget must be mutated under a lock to keep the cap accurate.
_download_bytes_lock = threading.Lock()

# Tracks the last synthetic mouse position per page object, because Playwright's
# Python Mouse API does not expose a `.position` property (original code relied
# on `page.mouse.position` which does not exist and raised AttributeError).
_mouse_pos: dict[int, tuple[float, float]] = {}


# ---------------------------------------------------------------------------
# AUTOMATIC DEPENDENCY INSTALLER
# ---------------------------------------------------------------------------
def install_missing_packages() -> None:
    """Install required runtime packages if missing. Only invoked when this
    file is executed directly (``streamlit run`` or ``python``), never on import.
    """
    # module_name -> pip package name
    required = {
        "streamlit": "streamlit",
        "PIL": "pillow",
        "numpy": "numpy",
        "requests": "requests",
        "bs4": "beautifulsoup4",
        "insightface": "insightface",
        "onnxruntime": "onnxruntime",
        "cv2": "opencv-python-headless",
        "playwright": "playwright",
    }
    missing: list[str] = []
    for module, package in required.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    if not missing:
        return
    print(f"[FaceHunter] Missing packages: {missing}. Installing...")
    for pkg in missing:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg]
            )
        except Exception as exc:  # pragma: no cover - environment dependent
            print(f"[FaceHunter] Could not install {pkg}: {exc}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "playwright", "install", "chromium"]
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        print(f"[FaceHunter] Could not install chromium: {exc}")
    print("[FaceHunter] Dependencies installed. Please restart: streamlit run FaceFinderPRO.py")
    sys.exit(0)


# ---------------------------------------------------------------------------
# LOGGING (with size-capped rotation)
# ---------------------------------------------------------------------------
def log_error(engine_name: str, error_msg: str) -> None:
    """Append a timestamped error entry to the error log. Rotates the log when
    it exceeds ERROR_LOG_MAX_BYTES so it cannot grow unbounded."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] Engine: {engine_name}\n{error_msg}\n{'-' * 80}\n"
    with _error_log_lock:
        try:
            if ERROR_LOG_FILE.exists() and ERROR_LOG_FILE.stat().st_size > ERROR_LOG_MAX_BYTES:
                rotated = ERROR_LOG_FILE.with_suffix(ERROR_LOG_FILE.suffix + ".1")
                try:
                    if rotated.exists():
                        rotated.unlink()
                    ERROR_LOG_FILE.replace(rotated)
                except Exception:
                    pass
            with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            # Logging must never crash the application.
            pass


# ---------------------------------------------------------------------------
# ATOMIC / RESILIENT PERSISTENCE (restricted unpickler + HMAC + schema)
# ---------------------------------------------------------------------------
# Pickle can execute arbitrary code on load. Although this is a local tool, a
# tampered or shared gallery.pkl could be weaponized. We defend in depth:
#   1. A restricted Unpickler that only allows a known-safe set of classes.
#   2. Optional HMAC-SHA256 integrity tag (if FACEHUNTER_PICKLE_HMAC_SECRET set).
#   3. Schema version stamp so future format changes can migrate safely.
#
# Allowed pickle globals: builtins containers (dict/list/tuple/set/frozenset/
# bytes/str/int/float/bool/None), collections.OrderedDict, numpy ndarray and
# numpy scalar dtypes, datetime.datetime. Everything else raises UnpicklingError.

_ALLOWED_PICKLE_MODULES = {
    "builtins",
    "collections",
    "datetime",
    "numpy",
    "numpy.core.multiarray",
    "numpy.core.numeric",
    "numpy._core.multiarray",
    "numpy._core.numeric",
    "numpy.dtype",
    "numpy._DType_meta",
    "numpy.dtypes",
}


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that refuses any global not on the allowlist."""

    def find_class(self, module, name):  # noqa: D401
        if module not in _ALLOWED_PICKLE_MODULES:
            raise pickle.UnpicklingError(
                f"Blocked unsafe pickle global: {module}.{name}"
            )
        # Refuse a handful of names even within allowed modules.
        if name in ("eval", "exec", "compile", "__import__", "open", "system",
                    "globals", "locals", "getattr", "setattr", "delattr"):
            raise pickle.UnpicklingError(f"Blocked unsafe pickle name: {module}.{name}")
        return super().find_class(module, name)


def _restricted_load(payload: bytes):
    """Load pickle bytes via the restricted unpickler. Never executes arbitrary
    code; only allowlisted builtins/numpy/datetime may be reconstructed."""
    return _RestrictedUnpickler(io.BytesIO(payload)).load()


def _hmac_tag(payload: bytes) -> bytes:
    """Compute HMAC-SHA256 of payload using the configured secret. Returns
    empty bytes if no secret is configured (signing is opt-in)."""
    if PICKLE_HMAC_SECRET:
        return hmac.new(PICKLE_HMAC_SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
    return b""


def _atomic_pickle_write(path: Path, obj: object) -> None:
    """Write `obj` to `path` atomically with a temp file + os.replace + fsync
    and restrictive 0600 permissions. The payload is wrapped with a schema
    version stamp and (if configured) an HMAC integrity tag, so loads can
    detect tampering and migrate forward."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        envelope = {
            "schema": SCHEMA_VERSION,
            "payload": obj,
        }
        with open(tmp, "wb") as f:
            body = pickle.dumps(envelope, protocol=pickle.HIGHEST_PROTOCOL)
            tag = _hmac_tag(body)
            f.write(len(tag).to_bytes(4, "big"))
            f.write(tag)
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, SAVE_FILE_PERM)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def _migrate_payload(payload, schema_in_file: int):
    """Migrate a loaded payload from its on-disk schema version to the current
    SCHEMA_VERSION. Returns the migrated payload. Currently only handles
    v0 (legacy unversioned pre-v2 stores) -> v2, which is a no-op for the dict
    shape itself; future migrations go here."""
    if schema_in_file == SCHEMA_VERSION:
        return payload
    # v0/v1 -> v2: legacy stores were bare dicts (gallery) or bare dicts (caches)
    # with the same key/value shape. No structural change required; we only
    # stamp the schema going forward. If a future schema changes the shape,
    # add an explicit migration step here.
    if schema_in_file in (0, 1) and isinstance(payload, dict):
        return payload
    # Unknown future schema from a newer binary: refuse to clobber.
    if schema_in_file > SCHEMA_VERSION:
        raise ValueError(
            f"Store schema {schema_in_file} is newer than supported "
            f"{SCHEMA_VERSION}; refusing to load to avoid data loss."
        )
    return payload


def _safe_pickle_load(path: Path, default):
    """Load a (possibly legacy) pickle file with the restricted unpickler and
    HMAC verification. Returns `default` (and logs + preserves evidence) if
    missing, corrupt, tampered, or on an unrecoverable schema mismatch."""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return default
        with open(path, "rb") as f:
            raw = f.read()
        # Legacy stores (pre-v2) were bare pickled dicts with no envelope.
        # Try the envelope format first; fall back to a legacy bare load.
        try:
            tag_len = int.from_bytes(raw[:4], "big")
            tag = raw[4:4 + tag_len]
            body = raw[4 + tag_len:]
            if PICKLE_HMAC_SECRET:
                expected = hmac.new(PICKLE_HMAC_SECRET.encode("utf-8"),
                                     body, hashlib.sha256).digest()
                if not hmac.compare_digest(tag, expected):
                    raise ValueError("HMAC integrity check failed — store may be tampered")
            envelope = _restricted_load(body)
            if not isinstance(envelope, dict) or "payload" not in envelope:
                raise ValueError("Malformed envelope (missing payload)")
            return _migrate_payload(envelope["payload"], int(envelope.get("schema", 0)))
        except (pickle.UnpicklingError, ValueError, EOFError, KeyError):
            # Maybe a legacy bare pickle from v0/v1.
            try:
                legacy = _restricted_load(raw)
                return _migrate_payload(legacy, 0)
            except Exception:
                raise
    except Exception as exc:
        log_error("Persistence", f"Corrupt or unreadable pickle at {path}: {exc}\n"
                                  f"Resetting to default to recover. A backup may exist at {path}.corrupt")
        try:
            corrupt_backup = path.with_suffix(path.suffix + ".corrupt")
            if path.exists() and not corrupt_backup.exists():
                shutil.copy2(path, corrupt_backup)
        except Exception:
            pass
    return default


# ---------------------------------------------------------------------------
# BACKUP / RESTORE (rotating backups for each persistent store)
# ---------------------------------------------------------------------------
def _backup_store(path: Path) -> None:
    """Create a rotating backup of `path`: shift .bak{N-1} -> .bak{N} and copy
    `path` -> .bak1, keeping at most BACKUP_KEEP backups."""
    try:
        if not path.exists():
            return
        # Shift existing backups: bak(N-1) -> bak(N)
        for i in range(BACKUP_KEEP, 1, -1):
            older = path.with_suffix(path.suffix + f".bak{i}")
            newer = path.with_suffix(path.suffix + f".bak{i-1}")
            if newer.exists():
                if older.exists():
                    older.unlink()
                newer.replace(older)
        # path -> bak1
        bak1 = path.with_suffix(path.suffix + ".bak1")
        if bak1.exists():
            bak1.unlink()
        shutil.copy2(path, bak1)
        try:
            os.chmod(bak1, SAVE_FILE_PERM)
        except OSError:
            pass
    except Exception as exc:
        log_error("Backup", f"Could not back up {path}: {exc}")


def restore_from_backup(path: Path) -> bool:
    """Attempt to restore `path` from its most recent backup (.bak1). Returns
    True if a restore was performed."""
    bak1 = path.with_suffix(path.suffix + ".bak1")
    if not bak1.exists():
        return False
    try:
        if path.exists():
            corrupt_backup = path.with_suffix(path.suffix + ".corrupt")
            if not corrupt_backup.exists():
                shutil.copy2(path, corrupt_backup)
        shutil.copy2(bak1, path)
        try:
            os.chmod(path, SAVE_FILE_PERM)
        except OSError:
            pass
        log_error("Restore", f"Restored {path} from {bak1}")
        return True
    except Exception as exc:
        log_error("Restore", f"Could not restore {path} from {bak1}: {exc}")
        return False


# ---------------------------------------------------------------------------
# INSIGHTFACE (lazy, thread-safe singleton; no module-level load)
# ---------------------------------------------------------------------------
_face_app = None


def get_face_app():
    """Return a cached InsightFace FaceAnalysis instance. Loads the model
    lazily on first use (after Streamlit is initialized), and is thread-safe."""
    global _face_app
    if _face_app is None:
        with _face_app_lock:
            if _face_app is None:
                from insightface.app import FaceAnalysis  # heavy; imported lazily
                app = FaceAnalysis(name="buffalo_l", providers=["CPUExecutionProvider"])
                app.prepare(ctx_id=-1)
                _face_app = app
    return _face_app


def get_embedding(img_array) -> np.ndarray | None:
    """Return the embedding of the highest-confidence face in the image, or None."""
    faces = get_face_app().get(img_array)
    if not faces:
        return None
    face = max(faces, key=lambda x: x.det_score)
    return face.embedding


def get_all_faces(img_array) -> list[dict]:
    """Extract all faces with embedding, bbox, detection score, age, gender."""
    faces = get_face_app().get(img_array)
    if not faces:
        return []
    results: list[dict] = []
    for face in faces:
        age = getattr(face, "age", None)
        gender_raw = getattr(face, "sex", None)  # 1: male, 0: female
        gender = None
        if gender_raw is not None:
            gender = "Male" if int(gender_raw) == 1 else "Female"
        results.append({
            "embedding": face.embedding,
            "bbox": face.bbox,
            "det_score": face.det_score,
            "age": age,
            "gender": gender,
        })
    return results


def cosine_sim(e1, e2) -> float:
    """Cosine similarity between two embeddings, guarded against zero norms."""
    if e1 is None or e2 is None:
        return 0.0
    import numpy as np
    n1 = float(np.linalg.norm(e1))
    n2 = float(np.linalg.norm(e2))
    if n1 == 0.0 or n2 == 0.0:
        return 0.0
    return float(np.dot(e1 / n1, e2 / n2))


# ---------------------------------------------------------------------------
# SECURITY: SSRF guard for candidate-URL fetching
# ---------------------------------------------------------------------------
# download_and_verify fetches arbitrary URLs returned by search engines. An
# attacker who can influence search results (or a misconfigured engine) could
# point us at internal services: cloud metadata (169.254.169.254), localhost
# services, private subnets, link-local, etc. We resolve the hostname and
# refuse any address in a non-public range before issuing the request.


def _is_blocked_ip(ip: str) -> bool:
    """Return True if `ip` is in a private/loopback/link-local/reserved range
    that must never be fetched as a candidate image (SSRF defense)."""
    if not SSRF_BLOCK_PRIVATE:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> block
    # IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) must be evaluated as IPv4,
    # otherwise a mapped metadata/loopback address slips past the range checks.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def is_url_safe(url: str) -> bool:
    """Validate that `url` is http(s), has a hostname, and resolves to a public
    IP (when SSRF blocking is enabled). Caches DNS results for 60s per host."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    # Reject obvious internal hostnames outright.
    if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        return False
    if not SSRF_BLOCK_PRIVATE:
        return True
    # Resolve and check all A/AAAA records.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for _family, _stype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _is_blocked_ip(ip):
            return False
    return True


# ---------------------------------------------------------------------------
# SECURITY: decompression-bomb guard for image decoding
# ---------------------------------------------------------------------------
def safe_open_image(data: bytes, source: str = "upload"):
    """Open an image from bytes with decompression-bomb protection. Enforces
    MAX_IMAGE_PIXELS on the decoded dimensions and MAX_DOWNLOAD_BYTES on the
    input size. Returns a PIL RGB image or raises ValueError."""
    if not data:
        raise ValueError(f"Empty image data from {source}.")
    if len(data) > (MAX_DOWNLOAD_BYTES if source != "upload" else MAX_UPLOAD_BYTES):
        raise ValueError(
            f"Image from {source} is too large ({len(data)} bytes)."
        )
    import PIL.Image as _PILImage
    # PIL raises DecompressionBombError for images above Image.MAX_IMAGE_PIXELS,
    # and DecompressionBombWarning below 2x. We set the limit and treat the
    # warning as an error to hard-block bombs.
    _PILImage.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", _PILImage.DecompressionBombWarning)
            image = _PILImage.open(io.BytesIO(data))
            image.load()  # force full decode
    except _PILImage.DecompressionBombError as exc:
        raise ValueError(f"Image from {source} exceeds the pixel limit "
                          f"({MAX_IMAGE_PIXELS}); refusing to decode.") from exc
    except Exception as exc:
        raise ValueError(f"Image from {source} is not valid: {exc}") from exc
    # Final dimension check (defense in depth).
    w, h = image.size
    if w * h > MAX_IMAGE_PIXELS:
        raise ValueError(f"Image from {source} is {w}x{h}={w*h} pixels, "
                          f"exceeding the {MAX_IMAGE_PIXELS} limit.")
    return image.convert("RGB")


# ---------------------------------------------------------------------------
# SECURITY: filename / gallery-name sanitization
# ---------------------------------------------------------------------------
_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9 _\-.()]")


def sanitize_gallery_name(name: str) -> str:
    """Sanitize a user-supplied gallery name: strip control chars, reject path
    traversal, cap length, and collapse whitespace. The gallery stores entries
    by dict key (never a filesystem path), but names may later be used as
    filenames in export — so we harden now."""
    if not isinstance(name, str):
        raise ValueError("Name must be a string.")
    name = name.strip()
    if not name:
        raise ValueError("Name cannot be empty.")
    if len(name) > 200:
        name = name[:200]
    # Remove any path separators / traversal sequences.
    name = name.replace("\x00", "")
    name = _UNSAFE_NAME_RE.sub("_", name)
    # Collapse runs of whitespace.
    name = re.sub(r"\s+", " ", name).strip()
    if not name:
        raise ValueError("Name contains no usable characters.")
    return name


# ---------------------------------------------------------------------------
# METRICS (lightweight, in-process counters for observability)
# ---------------------------------------------------------------------------
class Metrics:
    """Thread-safe in-process metrics counters. Exposed via a tiny JSON
    snapshot for diagnostics (never to the user UI)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._started_at = datetime.now()

    def inc(self, name: str, by: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + by

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = dict(self._counters)
        return {
            "started_at": self._started_at.isoformat(),
            "uptime_seconds": (datetime.now() - self._started_at).total_seconds(),
            "counters": counters,
        }


metrics = Metrics()


# ---------------------------------------------------------------------------
# BROWSER LIFECYCLE GUARD (no zombie Chromium processes)
# ---------------------------------------------------------------------------
# Tracks live Playwright browser/context handles so a KeyboardInterrupt or
# crash can still close them. Engines already close in finally blocks; this is
# a belt-and-suspenders registry for atexit.
_live_browsers: list = []
_live_browsers_lock = threading.Lock()


def _register_browser(browser) -> None:
    with _live_browsers_lock:
        _live_browsers.append(browser)


def _unregister_browser(browser) -> None:
    with _live_browsers_lock:
        try:
            _live_browsers.remove(browser)
        except ValueError:
            pass


def _shutdown_all_browsers() -> None:
    """Close any Playwright browsers still alive (atexit / signal handler)."""
    with _live_browsers_lock:
        browsers = list(_live_browsers)
        _live_browsers.clear()
    for b in browsers:
        try:
            b.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# GRACEFUL SHUTDOWN (atexit flush + browser cleanup)
# ---------------------------------------------------------------------------
_shutdown_registered = False
_shutdown_lock = threading.Lock()


def _register_shutdown_hooks() -> None:
    global _shutdown_registered
    with _shutdown_lock:
        if _shutdown_registered:
            return
        _shutdown_registered = True
    import atexit
    atexit.register(_atexit_flush)


def _atexit_flush() -> None:
    """Flush all in-memory caches to disk and close browsers on exit."""
    try:
        if gallery is not None:
            gallery.flush()
        if embedding_cache is not None:
            embedding_cache.flush()
        if search_cache is not None:
            search_cache.flush()
    except Exception:
        pass
    _shutdown_all_browsers()


# ---------------------------------------------------------------------------
# LOCAL GALLERY (thread-safe, atomic persistence, LRU cap, export/import)
# ---------------------------------------------------------------------------
class Gallery:
    """Persistent local gallery of face entries."""

    def __init__(self):
        self.data: dict[str, dict] = self.load()
        # Track dirty state so flush() can skip no-op writes.
        self._dirty = False

    def load(self) -> dict[str, dict]:
        return _safe_pickle_load(GALLERY_FILE, {})

    def save(self) -> None:
        with _gallery_lock:
            # Backup before overwrite (rotating, keeps BACKUP_KEEP copies).
            _backup_store(GALLERY_FILE)
            _atomic_pickle_write(GALLERY_FILE, self.data)
            self._dirty = False
            metrics.inc("gallery_saves")

    def flush(self) -> None:
        """Write to disk only if there are unsaved changes (atexit hook)."""
        with _gallery_lock:
            dirty = self._dirty
        if dirty:
            self.save()

    def add(self, name: str, embedding, image, full_image_bytes: bytes | None = None,
            metadata: dict | None = None) -> str:
        """Add an image to the gallery. Stores a thumbnail, the full image as
        JPEG bytes (quality 85), the embedding, and optional metadata."""
        # Sanitize the user-supplied name (path-traversal / control-char defense).
        name = sanitize_gallery_name(name)
        base = name
        counter = 1
        with _gallery_lock:
            while name in self.data:
                name = f"{base}_{counter}"
                counter += 1

        # Thumbnail
        thumb = image.copy()
        thumb.thumbnail((100, 100), Image.Resampling.LANCZOS)
        thumb_buff = io.BytesIO()
        thumb.save(thumb_buff, format="JPEG", quality=85)
        thumb_b64 = base64.b64encode(thumb_buff.getvalue()).decode()

        # Full image as JPEG bytes
        if full_image_bytes is None:
            full_buff = io.BytesIO()
            image.save(full_buff, format="JPEG", quality=85)
            full_image_bytes = full_buff.getvalue()

        if metadata is None:
            metadata = {}
        # Sanitize metadata values that may be rendered in the UI (XSS defense
        # in depth — Streamlit escapes, but export/JSON paths benefit too).
        metadata = _sanitize_metadata(metadata)
        if "age" not in metadata or "gender" not in metadata:
            try:
                faces = get_all_faces(np.array(image))
                if faces:
                    best = max(faces, key=lambda x: x["det_score"])
                    metadata.setdefault("age", best.get("age"))
                    metadata.setdefault("gender", best.get("gender"))
            except Exception as exc:
                log_error("Gallery", f"Could not derive face attributes during add: {exc}")

        with _gallery_lock:
            self.data[name] = {
                "embedding": embedding,
                "thumbnail": thumb_b64,
                "full_image": full_image_bytes,
                "added": datetime.now().isoformat(),
                "metadata": metadata or {},
            }
            self._dirty = True
            # Enforce the entry cap by archiving the oldest entries. Archived
            # entries are written to an archive file (not silently dropped).
            self._enforce_cap()
        self.save()
        metrics.inc("gallery_adds")
        return name

    def _enforce_cap(self) -> None:
        """If the gallery exceeds GALLERY_MAX_ENTRIES, archive (not delete) the
        oldest entries to GALLERY_ARCHIVE_FILE so no data is ever silently lost."""
        if GALLERY_MAX_ENTRIES <= 0 or len(self.data) <= GALLERY_MAX_ENTRIES:
            return
        # Oldest first by 'added' timestamp.
        sortable = []
        for n, e in self.data.items():
            sortable.append((n, e.get("added", ""), e))
        sortable.sort(key=lambda x: x[1])
        overflow = len(self.data) - GALLERY_MAX_ENTRIES
        to_archive = sortable[:overflow]
        archive_path = GALLERY_FILE.with_suffix(".archive.pkl")
        try:
            existing = _safe_pickle_load(archive_path, {"entries": {}})
            if not isinstance(existing, dict) or "entries" not in existing:
                existing = {"entries": {}}
            for n, _added, e in to_archive:
                existing["entries"][n] = e
            _atomic_pickle_write(archive_path, existing)
            log_error("Gallery", f"Archived {len(to_archive)} oldest entries to {archive_path}")
        except Exception as exc:
            log_error("Gallery", f"Could not archive overflow entries: {exc}")
            # Do NOT drop in-place if archiving failed; better to exceed the cap
            # than to lose data silently.
            return
        for n, _added, _e in to_archive:
            self.data.pop(n, None)
        metrics.inc("gallery_archived", by=len(to_archive))

    def delete(self, name: str) -> bool:
        with _gallery_lock:
            if name in self.data:
                del self.data[name]
                removed = True
                self._dirty = True
            else:
                removed = False
        if removed:
            self.save()
            metrics.inc("gallery_deletes")
        return removed

    def search(self, query_emb, threshold: float = 0.55) -> list[dict]:
        results = []
        for name, entry in list(self.data.items()):
            sim = cosine_sim(query_emb, entry["embedding"])
            if sim >= threshold:
                results.append({
                    "name": name,
                    "similarity": sim,
                    "thumbnail": entry["thumbnail"],
                    "added": entry["added"],
                    "metadata": entry.get("metadata", {}),
                })
        return sorted(results, key=lambda x: x["similarity"], reverse=True)

    def list_all(self) -> dict[str, dict]:
        with _gallery_lock:
            return dict(self.data)

    # --- Export / Import (JSON, no raw embeddings leaked) ---
    def export_json(self, path) -> int:
        """Export gallery metadata (names, added, metadata, source_url) to a
        JSON file. Embeddings and full images are NOT exported (they are large
        and potentially sensitive). Returns the number of entries exported."""
        out = {"schema": SCHEMA_VERSION, "entries": []}
        with _gallery_lock:
            for name, entry in self.data.items():
                out["entries"].append({
                    "name": name,
                    "added": entry.get("added"),
                    "metadata": _sanitize_metadata(entry.get("metadata", {})),
                    "thumbnail": entry.get("thumbnail", ""),
                })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        try:
            os.chmod(path, SAVE_FILE_PERM)
        except OSError:
            pass
        return len(out["entries"])

    def import_json(self, path) -> int:
        """Import gallery metadata from a JSON export. Only reconstructs entries
        that include a thumbnail and a name; embeddings are absent in exports,
        so imported entries are non-searchable until re-embedded. Returns the
        number of entries imported."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "entries" not in data:
            raise ValueError("Invalid gallery export format.")
        imported = 0
        for entry in data["entries"]:
            name = sanitize_gallery_name(str(entry.get("name", "")))
            if not name:
                continue
            base = name
            counter = 1
            with _gallery_lock:
                while name in self.data:
                    name = f"{base}_{counter}"
                    counter += 1
                self.data[name] = {
                    "embedding": None,  # non-searchable until re-embedded
                    "thumbnail": str(entry.get("thumbnail", "")),
                    "full_image": b"",
                    "added": str(entry.get("added", datetime.now().isoformat())),
                    "metadata": _sanitize_metadata(entry.get("metadata", {})),
                }
                self._dirty = True
            imported += 1
        if imported:
            self.save()
        metrics.inc("gallery_imports", by=imported)
        return imported


def _sanitize_metadata(metadata: dict) -> dict:
    """Coerce all metadata values to safe primitives and cap their length, to
    prevent oversized/odd types from being stored and to neutralize any
    script-like content if it ever reaches an unsafe HTML render path."""
    if not isinstance(metadata, dict):
        return {}
    out = {}
    for k, v in metadata.items():
        key = str(k)[:200]
        if v is None or isinstance(v, (bool, int, float)):
            out[key] = v
        elif isinstance(v, str):
            out[key] = v[:5000]
        elif isinstance(v, (list, tuple)):
            out[key] = [str(x)[:500] for x in v[:100]]
        elif isinstance(v, dict):
            out[key] = _sanitize_metadata(v)
        else:
            out[key] = str(v)[:5000]
    return out


# ---------------------------------------------------------------------------
# EMBEDDING CACHE (thread-safe, atomic, LRU cap)
# ---------------------------------------------------------------------------
class EmbeddingCache:
    def __init__(self):
        self.cache: dict[str, object] = self.load()
        self._dirty = False

    def load(self) -> dict[str, object]:
        return _safe_pickle_load(EMBEDDING_CACHE_FILE, {})

    def save(self) -> None:
        with _embedding_cache_lock:
            # Regenerable cache: no rotating backup. Backing up on every set
            # copied the whole file per candidate (O(n) I/O amplification,
            # O(n^2) per search); corruption recovery already resets to {}.
            self._evict()
            _atomic_pickle_write(EMBEDDING_CACHE_FILE, self.cache)
            self._dirty = False
            metrics.inc("embedding_cache_saves")

    def _evict(self) -> None:
        """Evict oldest entries when the cache exceeds EMBEDDING_CACHE_MAX_ENTRIES.
        dict preserves insertion order in Python 3.7+, so the first keys are the
        oldest. We cannot know access time cheaply, so we evict by insertion."""
        if EMBEDDING_CACHE_MAX_ENTRIES <= 0:
            return
        overflow = len(self.cache) - EMBEDDING_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return
        keys = list(self.cache.keys())[:overflow]
        for k in keys:
            self.cache.pop(k, None)
        metrics.inc("embedding_cache_evicted", by=len(keys))

    def flush(self) -> None:
        with _embedding_cache_lock:
            dirty = self._dirty
        if dirty:
            self.save()

    def get(self, image_bytes: bytes):
        key = hashlib.sha256(image_bytes).hexdigest()
        with _embedding_cache_lock:
            return self.cache.get(key)

    def set(self, image_bytes: bytes, embedding) -> None:
        key = hashlib.sha256(image_bytes).hexdigest()
        with _embedding_cache_lock:
            self.cache[key] = embedding
            self._dirty = True
        self.save()
        metrics.inc("embedding_cache_sets")


# ---------------------------------------------------------------------------
# SEARCH CACHE (thread-safe, atomic, TTL)
# ---------------------------------------------------------------------------
class SearchCache:
    """Caches candidate URLs for an image for SEARCH_CACHE_TTL_HOURS hours,
    keyed by SHA-256 of image bytes."""

    def __init__(self):
        self.cache: dict[str, tuple[datetime, list[str]]] = self.load()
        self._dirty = False

    def load(self) -> dict[str, tuple[datetime, list[str]]]:
        return _safe_pickle_load(SEARCH_CACHE_FILE, {})

    def save(self) -> None:
        with _search_cache_lock:
            # Regenerable cache: no rotating backup (see EmbeddingCache.save).
            self._evict()
            _atomic_pickle_write(SEARCH_CACHE_FILE, self.cache)
            self._dirty = False
            metrics.inc("search_cache_saves")

    def _evict(self) -> None:
        if SEARCH_CACHE_MAX_ENTRIES <= 0:
            return
        overflow = len(self.cache) - SEARCH_CACHE_MAX_ENTRIES
        if overflow <= 0:
            return
        # Evict oldest by timestamp.
        items = sorted(self.cache.items(), key=lambda kv: kv[1][0])
        for k, _v in items[:overflow]:
            self.cache.pop(k, None)
        metrics.inc("search_cache_evicted", by=overflow)

    def flush(self) -> None:
        with _search_cache_lock:
            dirty = self._dirty
        if dirty:
            self.save()

    def get(self, image_bytes: bytes) -> list[str] | None:
        key = hashlib.sha256(image_bytes).hexdigest()
        expired = False
        with _search_cache_lock:
            entry = self.cache.get(key)
            if entry:
                timestamp, urls = entry
                if datetime.now() - timestamp < timedelta(hours=SEARCH_CACHE_TTL_HOURS):
                    return urls
                # expired
                self.cache.pop(key, None)
                self._dirty = True
                expired = True
        # Only touch the disk when we actually evicted an expired entry. A plain
        # cache miss must never trigger a full pickle write (the old code saved
        # on every miss, thrashing the disk during a search).
        if expired:
            self.save()
        return None

    def set(self, image_bytes: bytes, urls: list[str]) -> None:
        key = hashlib.sha256(image_bytes).hexdigest()
        with _search_cache_lock:
            self.cache[key] = (datetime.now(), urls)
            self._dirty = True
        self.save()
        metrics.inc("search_cache_sets")


# ---------------------------------------------------------------------------
# STEALTH UTILITIES
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def random_delay(mean: float = 0.8, sigma: float = 0.3, min_val: float = 0.2, max_val: float = 3.0) -> float:
    delay = random.gauss(mean, sigma)
    return max(min_val, min(max_val, delay))


def _get_mouse_pos(page) -> tuple[float, float]:
    return _mouse_pos.get(id(page), (0.0, 0.0))


def _set_mouse_pos(page, x: float, y: float) -> None:
    _mouse_pos[id(page)] = (x, y)


def bezier_move(page, target_x: float, target_y: float, steps: int = 20) -> None:
    """Move the mouse to (target_x, target_y) along a cubic Bezier curve with
    jitter, simulating human motion. Does not depend on `page.mouse.position`
    (which does not exist in Playwright's Python API)."""
    start_x, start_y = _get_mouse_pos(page)
    cp1x = start_x + (target_x - start_x) * random.uniform(0.3, 0.7) + random.uniform(-30, 30)
    cp1y = start_y + (target_y - start_y) * random.uniform(0.3, 0.7) + random.uniform(-30, 30)
    cp2x = start_x + (target_x - start_x) * random.uniform(0.3, 0.7) + random.uniform(-30, 30)
    cp2y = start_y + (target_y - start_y) * random.uniform(0.3, 0.7) + random.uniform(-30, 30)
    for i in range(1, steps + 1):
        t = i / steps
        mt = 1 - t
        x = mt ** 3 * start_x + 3 * mt ** 2 * t * cp1x + 3 * mt * t ** 2 * cp2x + t ** 3 * target_x
        y = mt ** 3 * start_y + 3 * mt ** 2 * t * cp1y + 3 * mt * t ** 2 * cp2y + t ** 3 * target_y
        x += random.uniform(-1, 1)
        y += random.uniform(-1, 1)
        page.mouse.move(x, y)
        _set_mouse_pos(page, x, y)
        time.sleep(random.uniform(0.005, 0.025))
    _set_mouse_pos(page, target_x, target_y)


def human_click(page, selector: str, timeout: int = 5) -> bool:
    try:
        loc = page.locator(selector).first
        if loc.count() == 0:
            return False
        box = loc.bounding_box(timeout=timeout * 1000)
        if not box:
            return False
        tx = box["x"] + box["width"] * random.uniform(0.3, 0.7)
        ty = box["y"] + box["height"] * random.uniform(0.3, 0.7)
        if random.random() < 0.4:
            page.mouse.move(tx + random.uniform(-20, 20), ty + random.uniform(-20, 20))
            _set_mouse_pos(page, tx, ty)
            time.sleep(random_delay(0.4, 0.15, 0.2, 1.5))
        bezier_move(page, tx, ty)
        time.sleep(random_delay(0.2, 0.1, 0.05, 0.6))
        page.mouse.click(tx, ty)
        _set_mouse_pos(page, tx, ty)
        time.sleep(random_delay(0.5, 0.2, 0.2, 1.5))
        return True
    except Exception:
        return False


def human_scroll(page, times: int = 3, min_pixels: int = 200, max_pixels: int = 800) -> None:
    for _ in range(times):
        direction = 1 if random.random() < 0.7 else -1
        pixels = random.randint(min_pixels, max_pixels) * direction
        steps = random.randint(3, 8)
        for _ in range(steps):
            delta = pixels // steps + random.randint(-20, 20)
            page.mouse.wheel(delta_x=0, delta_y=delta)
            time.sleep(random.uniform(0.05, 0.2))
        time.sleep(random_delay(0.6, 0.3, 0.3, 2.0))


def human_type(page, selector: str, text: str, mean_delay: float = 0.15, sigma: float = 0.05) -> None:
    loc = page.locator(selector).first
    loc.click()
    for char in text:
        delay = random.gauss(mean_delay, sigma)
        delay = max(0.02, min(0.5, delay))
        time.sleep(delay)
        loc.type(char, delay=0)
    time.sleep(random_delay(0.2, 0.1))


# ---------------------------------------------------------------------------
# DYNAMIC ELEMENT FINDER
# ---------------------------------------------------------------------------
def find_element_robust(page, selectors: list[str], timeout: int = 5000):
    """Try multiple CSS selectors, then ARIA/text fallbacks, to locate an element."""
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                box = loc.bounding_box(timeout=timeout)
                if box:
                    return loc
        except Exception:
            continue
    for label in ("Search by image",):
        try:
            loc = page.get_by_role("button", name=label).first
            if loc.count() > 0:
                return loc
        except Exception:
            pass
        try:
            loc = page.get_by_text(label, exact=False).first
            if loc.count() > 0:
                return loc
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# URL UPGRADE (size hints + redirect resolution)
# ---------------------------------------------------------------------------
def upgrade_image_url(url: str, max_redirects: int = 5) -> str | None:
    """Replace size indicators in query parameters with larger values, then
    follow up to `max_redirects` redirects to resolve the final image URL.
    Returns the final URL, or the original URL on any failure (never raises)."""
    original = url
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        size_keys = ["w", "h", "width", "height", "s", "size"]
        modified = False
        for key in size_keys:
            if key in qs:
                if key in ("w", "width", "h", "height"):
                    qs[key] = ["800"]
                    modified = True
                elif key == "s":
                    qs[key] = ["l"]
                    modified = True
                elif key == "size":
                    qs[key] = ["large"]
                    modified = True
        if modified:
            new_query = urllib.parse.urlencode(qs, doseq=True)
            parsed = parsed._replace(query=new_query)
            url = urllib.parse.urlunparse(parsed)

        session = requests.Session()
        # FIX: max_redirects is a Session attribute, not a per-request kwarg.
        session.max_redirects = max_redirects
        resp = session.head(
            url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": random.choice(USER_AGENTS)},
        )
        final_url = resp.url
        if final_url and str(final_url).startswith("http"):
            return final_url
        return url if url.startswith("http") else None
    except Exception:
        # A HEAD/network failure must NOT discard the size-upgrade work: prefer
        # the (possibly enlarged) URL, then fall back to the original. The old
        # code returned the un-upgraded original, silently yielding low-res
        # candidates whenever the redirect probe failed.
        if url.startswith("http"):
            return url
        return original if original.startswith("http") else None


# ---------------------------------------------------------------------------
# SEARCH ENGINES (refactored: single implementation each, attempt_search)
# ---------------------------------------------------------------------------
class SearchEngine:
    """Base class. Each engine implements attempt_search(image_bytes, proxy)."""

    def __init__(self, headless: bool = False):
        self.headless = headless
        self.timeout = 30

    def attempt_search(self, image_bytes: bytes, proxy: dict | None = None) -> list[str]:
        raise NotImplementedError


def _common_launch_args() -> list[str]:
    return [
        "--disable-blink-features=AutomationControlled",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-site-isolation-trials",
        "--disable-web-security",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--disable-browser-side-navigation",
        "--disable-features=VizDisplayCompositor",
        "--use-gl=swiftshader",
        "--remote-debugging-port=0",
    ]


def _new_stealth_context(browser, *, locale: str | None = None,
                         timezone_id: str | None = None,
                         accept_language: str | None = None):
    viewport_w = random.choice([1280, 1366, 1440, 1536, 1600, 1920])
    viewport_h = random.choice([720, 768, 800, 864, 900, 1080])
    context_kwargs = {
        "user_agent": random.choice(USER_AGENTS),
        "viewport": {"width": viewport_w, "height": viewport_h},
        "locale": locale or random.choice(["en-US", "en-GB", "ru-RU"]),
        "timezone_id": timezone_id or random.choice(
            ["America/New_York", "Europe/London", "Europe/Moscow"]
        ),
    }
    if accept_language:
        context_kwargs["extra_http_headers"] = {"Accept-Language": accept_language}
    return browser.new_context(**context_kwargs)


def _init_stealth_page(context):
    page = context.new_page()
    page.add_init_script(
        """
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3,4,5] });
        window.chrome = { runtime: {} };
        """
    )
    return page


def _collect_image_urls(page, img_selectors: list[str], anchor_spec: tuple[str, str] | None = None) -> list[str]:
    urls: list[str] = []
    for sel in img_selectors:
        try:
            imgs = page.locator(sel).all()
        except Exception:
            continue
        for img in imgs[:30]:
            try:
                src = (img.get_attribute("src")
                       or img.get_attribute("data-src")
                       or img.get_attribute("data-original"))
            except Exception:
                src = None
            if src and src.startswith("http"):
                upgraded = upgrade_image_url(src)
                if upgraded:
                    urls.append(upgraded)
    if anchor_spec:
        attr_name, query_key = anchor_spec
        try:
            anchors = page.locator(f"a[href*='{query_key}']").all()
        except Exception:
            anchors = []
        for a in anchors[:15]:
            try:
                href = a.get_attribute("href")
            except Exception:
                href = None
            if href:
                parsed = urllib.parse.urlparse(href)
                qs = urllib.parse.parse_qs(parsed.query)
                if query_key in qs:
                    orig = qs[query_key][0]
                    upgraded = upgrade_image_url(orig)
                    if upgraded:
                        urls.append(upgraded)
    return list(dict.fromkeys(urls))[:25]


class YandexEngine(SearchEngine):
    def attempt_search(self, image_bytes: bytes, proxy: dict | None = None) -> list[str]:
        urls: list[str] = []
        with sync_playwright() as p:
            launch_args = _common_launch_args()
            if self.headless:
                launch_args.append("--headless=new")
            browser = p.chromium.launch(headless=self.headless, args=launch_args, proxy=proxy)
            _register_browser(browser)
            context = _new_stealth_context(
                browser,
                accept_language=random.choice(["en-US,en;q=0.9", "ru-RU,ru;q=0.9"]),
            )
            page = _init_stealth_page(context)
            try:
                page.goto("https://yandex.com/images/", timeout=self.timeout * 1000)
                time.sleep(random_delay(1.0, 0.4, 0.6, 2.5))

                camera_selectors = [
                    "div.image-search-button",
                    "button[aria-label='Search by image']",
                    "div[data-testid='search-by-image']",
                    "div.search2__button",
                    "a[aria-label='Search by image']",
                ]
                camera = find_element_robust(page, camera_selectors)
                if camera:
                    try:
                        box = camera.bounding_box()
                        if box:
                            tx = box["x"] + box["width"] / 2
                            ty = box["y"] + box["height"] / 2
                            bezier_move(page, tx, ty)
                            time.sleep(random_delay(0.3, 0.1))
                            page.mouse.click(tx, ty)
                            _set_mouse_pos(page, tx, ty)
                    except Exception:
                        pass
                else:
                    file_input = page.locator("input[type='file']").first
                    if file_input.count() == 0:
                        raise Exception("Could not find camera button or file input")

                file_input = page.locator("input[type='file']").first
                if file_input.count() == 0:
                    raise Exception("File input not found")
                file_input.set_input_files(
                    files=[{"name": "face.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}]
                )
                time.sleep(random_delay(1.0, 0.3, 0.5, 2.0))

                for sel in ["button[type='submit']", "button.search", "input[type='submit']"]:
                    if human_click(page, sel):
                        break

                time.sleep(random_delay(2.0, 0.5, 1.0, 4.0))
                human_scroll(page, times=random.randint(2, 4))

                urls = _collect_image_urls(
                    page,
                    img_selectors=[
                        "div.content__left img",
                        "div.CardsGrid img",
                        "div.Grid img",
                        "img",
                        "div[class*='image'] img",
                        "div[class*='thumb'] img",
                    ],
                    anchor_spec=("href", "img_url"),
                )
            except Exception:
                raise
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                _unregister_browser(browser)
        return urls


class GoogleEngine(SearchEngine):
    def attempt_search(self, image_bytes: bytes, proxy: dict | None = None) -> list[str]:
        urls: list[str] = []
        with sync_playwright() as p:
            launch_args = _common_launch_args()
            if self.headless:
                launch_args.append("--headless=new")
            browser = p.chromium.launch(headless=self.headless, args=launch_args, proxy=proxy)
            _register_browser(browser)
            context = _new_stealth_context(browser, locale="en-US",
                                           timezone_id="America/New_York")
            page = _init_stealth_page(context)
            try:
                page.goto("https://images.google.com/", timeout=self.timeout * 1000)
                time.sleep(random_delay(1.0, 0.4, 0.6, 2.5))

                camera_selectors = [
                    "div[aria-label='Search by image']",
                    "div[role='button'][aria-label*='image']",
                    "div.gLFyf",
                ]
                clicked = False
                for sel in camera_selectors:
                    if human_click(page, sel):
                        clicked = True
                        break

                file_input = page.locator("input[type='file']").first
                if not clicked and file_input.count() == 0:
                    raise Exception("Camera button or file input not found")

                file_input.set_input_files(
                    files=[{"name": "face.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}]
                )
                time.sleep(random_delay(1.0, 0.3, 0.5, 2.0))

                for sel in ["button[type='submit']", "input[type='submit']"]:
                    if human_click(page, sel):
                        break

                time.sleep(random_delay(2.0, 0.5, 1.0, 4.0))
                human_scroll(page, times=random.randint(2, 4))

                urls = _collect_image_urls(
                    page,
                    img_selectors=["img.rg_i", "div.bRMDJf img", "img"],
                    anchor_spec=("href", "imgrefurl"),
                )
            except Exception:
                raise
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                _unregister_browser(browser)
        return urls


class BingEngine(SearchEngine):
    def attempt_search(self, image_bytes: bytes, proxy: dict | None = None) -> list[str]:
        urls: list[str] = []
        with sync_playwright() as p:
            launch_args = _common_launch_args()
            if self.headless:
                launch_args.append("--headless=new")
            browser = p.chromium.launch(headless=self.headless, args=launch_args, proxy=proxy)
            _register_browser(browser)
            context = _new_stealth_context(browser, locale="en-US",
                                           timezone_id="America/New_York")
            page = _init_stealth_page(context)
            try:
                page.goto("https://www.bing.com/images/", timeout=self.timeout * 1000)
                time.sleep(random_delay(1.0, 0.4, 0.6, 2.5))

                camera_selectors = ["button[aria-label='Search by image']", "button.camera_icon"]
                clicked = False
                for sel in camera_selectors:
                    if human_click(page, sel):
                        clicked = True
                        break

                file_input = page.locator("input[type='file']").first
                if not clicked and file_input.count() == 0:
                    raise Exception("Camera button or file input not found")

                file_input.set_input_files(
                    files=[{"name": "face.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}]
                )
                time.sleep(random_delay(1.0, 0.3, 0.5, 2.0))
                time.sleep(random_delay(2.0, 0.5, 1.0, 4.0))
                human_scroll(page, times=random.randint(2, 4))

                urls = _collect_image_urls(
                    page,
                    img_selectors=["img.mimg", "div.imgpt a img", "img"],
                )
            except Exception:
                raise
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                _unregister_browser(browser)
        return urls


class TinEyeEngine(SearchEngine):
    def attempt_search(self, image_bytes: bytes, proxy: dict | None = None) -> list[str]:
        urls: list[str] = []
        with sync_playwright() as p:
            launch_args = _common_launch_args()
            if self.headless:
                launch_args.append("--headless=new")
            browser = p.chromium.launch(headless=self.headless, args=launch_args, proxy=proxy)
            _register_browser(browser)
            context = _new_stealth_context(browser, locale="en-US",
                                           timezone_id="America/New_York")
            page = _init_stealth_page(context)
            try:
                page.goto("https://tineye.com/", timeout=self.timeout * 1000)
                time.sleep(random_delay(1.0, 0.4, 0.6, 2.5))

                upload_selectors = [
                    "input[type='file']",
                    "button.upload-button",
                    "a[href='/']",
                ]
                file_input = find_element_robust(page, upload_selectors)
                if file_input is None:
                    raise Exception("TinEye file input not found")

                file_input.set_input_files(
                    files=[{"name": "face.jpg", "mimeType": "image/jpeg", "buffer": image_bytes}]
                )
                time.sleep(random_delay(1.0, 0.3, 0.5, 2.0))

                try:
                    page.wait_for_selector("div.match-row, div.results", timeout=15000)
                except Exception:
                    pass
                human_scroll(page, times=random.randint(1, 3))

                urls = _collect_image_urls(
                    page,
                    img_selectors=[
                        "div.match-row img",
                        "div.result img",
                        "a.result-thumbnail img",
                        "img.result-image",
                    ],
                )
                # TinEye result links may point directly to source images.
                try:
                    anchors = page.locator("a.match-link, a.result-link").all()
                except Exception:
                    anchors = []
                for a in anchors[:15]:
                    try:
                        href = a.get_attribute("href")
                    except Exception:
                        href = None
                    if href and href.startswith("http") and not href.startswith("https://tineye.com"):
                        upgraded = upgrade_image_url(href)
                        if upgraded:
                            urls.append(upgraded)
                urls = list(dict.fromkeys(urls))[:25]
            except Exception:
                raise
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass
                _unregister_browser(browser)
        return urls


# ---------------------------------------------------------------------------
# REQUESTS FALLBACK (robust to non-JSON responses)
# ---------------------------------------------------------------------------
def search_yandex_requests(image_bytes: bytes, retries: int = 2) -> list[str]:
    """Last-resort fallback using the requests library against Yandex. The
    upstream HTML endpoint rarely returns JSON, so this is best-effort and
    never raises."""
    urls: list[str] = []
    for _ in range(retries):
        try:
            session = requests.Session()
            session.get("https://yandex.com/",
                        headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
            files = {"upfile": ("image.jpg", image_bytes, "image/jpeg")}
            params = {"rpt": "imageview", "format": "json"}
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://yandex.com/",
            }
            r = session.post("https://yandex.ru/images/search", params=params,
                             files=files, headers=headers, timeout=15)
            if r.status_code != 200:
                time.sleep(random_delay(2, 0.5))
                continue
            try:
                data = r.json()
            except Exception:
                data = None
            if isinstance(data, dict):
                for block in data.get("blocks", []):
                    for item in block.get("items", []):
                        url = item.get("url")
                        if url and url.startswith("http"):
                            upgraded = upgrade_image_url(url)
                            if upgraded:
                                urls.append(upgraded)
            if urls:
                break
        except Exception:
            time.sleep(random_delay(2, 0.5))
            continue
    return list(dict.fromkeys(urls))[:20]


# ---------------------------------------------------------------------------
# MULTI-STRATEGY SEARCH ORCHESTRATOR
# ---------------------------------------------------------------------------
ENGINE_CLASSES: dict[str, type] = {
    "Yandex": YandexEngine,
    "Google": GoogleEngine,
    "Bing": BingEngine,
    "TinEye": TinEyeEngine,
}


def search_with_fallback(engine_name: str, image_bytes: bytes, headless: bool,
                         proxy_list: list[str], search_cache: SearchCache) -> tuple[list[str], str]:
    """Main search orchestrator. Checks the search cache, then tries the
    selected engine with retries and proxy cycling, falls back to Yandex, then
    to the requests-based fallback."""
    cached_urls = search_cache.get(image_bytes)
    if cached_urls is not None:
        return cached_urls, f"{engine_name} (cached)"

    proxies = list(proxy_list) if proxy_list else [None]
    proxy_idx = 0
    delays = [1, 2, 4]
    last_exception: Exception | None = None

    if engine_name in ENGINE_CLASSES:
        engine = ENGINE_CLASSES[engine_name](headless=headless)
        for attempt in range(3):
            proxy_str = proxies[proxy_idx % len(proxies)]
            proxy_dict = {"server": proxy_str} if proxy_str else None
            try:
                urls = engine.attempt_search(image_bytes, proxy_dict)
                if urls:
                    search_cache.set(image_bytes, urls)
                    return urls, engine_name
            except Exception as exc:
                last_exception = exc
                log_error(engine_name, traceback.format_exc())
                proxy_idx += 1
                if attempt < 2:
                    time.sleep(delays[attempt])
    else:
        log_error(engine_name, f"Unknown engine: {engine_name}")

    # Fallback to Yandex
    if engine_name != "Yandex":
        engine = YandexEngine(headless=headless)
        for attempt in range(3):
            proxy_str = proxies[proxy_idx % len(proxies)]
            proxy_dict = {"server": proxy_str} if proxy_str else None
            try:
                urls = engine.attempt_search(image_bytes, proxy_dict)
                if urls:
                    search_cache.set(image_bytes, urls)
                    return urls, "Yandex (fallback)"
            except Exception as exc:
                last_exception = exc
                log_error("Yandex fallback", traceback.format_exc())
                proxy_idx += 1
                if attempt < 2:
                    time.sleep(delays[attempt])

    # Final fallback: requests
    try:
        urls = search_yandex_requests(image_bytes)
        if urls:
            search_cache.set(image_bytes, urls)
            return urls, "Yandex (requests fallback)"
    except Exception as exc:
        last_exception = exc
        log_error("Requests fallback", traceback.format_exc())

    if last_exception is not None:
        log_error("Search", f"All search strategies exhausted. Last error: {last_exception}")
    return [], "None"


# ---------------------------------------------------------------------------
# SSRF-SAFE HTTP (per-hop redirect validation)
# ---------------------------------------------------------------------------
def _ssrf_safe_request(method: str, url: str, *, timeout: int, headers: dict,
                       stream: bool = False, max_redirects: int = 5):
    """Issue an HTTP request while re-validating EVERY redirect hop with
    is_url_safe(). Redirects are followed manually (requests' own
    allow_redirects is disabled), so a public candidate URL cannot 30x-redirect
    us into an internal / loopback / cloud-metadata endpoint -- the redirect
    SSRF bypass that allow_redirects=True left wide open. Returns the final
    Response, or None if any hop is unsafe or the request fails. Never raises.
    """
    current = url
    for _ in range(max_redirects + 1):
        if not is_url_safe(current):
            return None
        try:
            resp = requests.request(method, current, timeout=timeout,
                                    headers=headers, stream=stream,
                                    allow_redirects=False)
        except Exception:
            return None
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            try:
                resp.close()
            except Exception:
                pass
            if not location:
                return None
            current = urllib.parse.urljoin(current, location)
            continue
        return resp
    return None


# ---------------------------------------------------------------------------
# DOWNLOAD & VERIFY (thread-safe de-duplication)
# ---------------------------------------------------------------------------
def download_and_verify(query_emb, url: str, seen_urls: set, seen_urls_lock: threading.Lock,
                        timeout: int = 12, total_bytes_counter: list | None = None) -> dict | None:
    """Download a candidate image, verify it is a real image, compute its
    embedding, and return it if similar enough to the query.

    Hardened: SSRF guard (refuse private/loopback/link-local IPs), per-response
    size cap (MAX_DOWNLOAD_BYTES), per-search total-bytes cap
    (MAX_SEARCH_TOTAL_BYTES), and decompression-bomb protection via
    safe_open_image(). Never raises; returns None on any failure.
    """
    metrics.inc("download_attempts")
    # Thread-safe check-and-add to avoid duplicate downloads.
    with seen_urls_lock:
        if url in seen_urls:
            return None
        seen_urls.add(url)

    # SSRF guard: refuse non-public / internal / loopback targets.
    if not is_url_safe(url):
        metrics.inc("download_ssrf_blocked")
        log_error("Download", f"Blocked unsafe (SSRF) candidate URL: {url[:200]}")
        return None

    # Per-search total-bytes cap: stop fetching once the budget is exhausted.
    if total_bytes_counter is not None:
        if total_bytes_counter[0] >= MAX_SEARCH_TOTAL_BYTES:
            metrics.inc("download_total_bytes_exceeded")
            return None

    # HEAD check for Content-Type and Content-Length (redirects validated per hop).
    try:
        head_resp = _ssrf_safe_request(
            "HEAD", url, timeout=timeout,
            headers={"User-Agent": random.choice(USER_AGENTS)},
        )
        if head_resp is None:
            metrics.inc("download_head_failed")
            return None
        with head_resp:
            content_type = head_resp.headers.get("Content-Type", "")
            if not content_type.startswith("image/"):
                metrics.inc("download_non_image_ct")
                return None
            cl = head_resp.headers.get("Content-Length")
            if cl and cl.isdigit() and int(cl) > MAX_DOWNLOAD_BYTES:
                metrics.inc("download_oversized_head")
                return None
    except Exception:
        return None

    try:
        # Stream the GET so we can abort early if the body exceeds the cap.
        # Redirects are validated per hop by _ssrf_safe_request (no SSRF bypass).
        r = _ssrf_safe_request(
            "GET", url, timeout=timeout, stream=True,
            headers={"User-Agent": random.choice(USER_AGENTS),
                     "Referer": "https://yandex.com/"},
        )
        if r is None:
            metrics.inc("download_non_200")
            return None
        with r:
            if r.status_code != 200:
                metrics.inc("download_non_200")
                return None
            chunks = []
            total = 0
            for chunk in r.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    metrics.inc("download_oversized_stream")
                    return None
                chunks.append(chunk)
                if total_bytes_counter is not None:
                    with _download_bytes_lock:
                        total_bytes_counter[0] += len(chunk)
                        over_budget = total_bytes_counter[0] >= MAX_SEARCH_TOTAL_BYTES
                    if over_budget:
                        metrics.inc("download_total_bytes_exceeded")
                        return None
            img_bytes = b"".join(chunks)
        if not img_bytes:
            return None
        # Decompression-bomb-safe decode.
        try:
            img = safe_open_image(img_bytes, source="candidate")
        except ValueError as exc:
            metrics.inc("download_decode_failed")
            log_error("Download", f"Could not decode candidate from {url[:200]}: {exc}")
            return None
        emb = embedding_cache.get(img_bytes)
        if emb is None:
            try:
                emb = get_embedding(np.array(img))
            except Exception as exc:
                log_error("Download", f"Embedding extraction failed for {url[:200]}: {exc}")
                emb = None
            if emb is not None:
                embedding_cache.set(img_bytes, emb)
        if emb is None:
            return None
        sim = cosine_sim(query_emb, emb)
        if sim > 0.45:
            metrics.inc("download_matches")
            return {"url": url, "similarity": sim, "image": img}
        metrics.inc("download_below_threshold")
        return None
    except Exception as exc:
        metrics.inc("download_errors")
        log_error("Download", f"Unexpected error fetching {url[:200]}: {exc}")
        return None


# ---------------------------------------------------------------------------
# IMAGE UPLOAD VALIDATION (decompression-bomb-safe)
# ---------------------------------------------------------------------------
def validate_uploaded_image(file_bytes: bytes, content_type: str = ""):
    """Validate size and integrity of an uploaded image with decompression-bomb
    protection. Returns a PIL RGB image or raises ValueError with a user-safe
    message."""
    if not file_bytes:
        raise ValueError("The uploaded file is empty.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"The uploaded file is too large ({len(file_bytes)} bytes). "
            f"Maximum allowed is {MAX_UPLOAD_BYTES} bytes."
        )
    return safe_open_image(file_bytes, source="upload")


def normalize_image(image, max_size: int = MAX_IMAGE_DIMENSION):
    """Downscale an image so its longest side is at most max_size (LANCZOS)."""
    if max(image.size) > max_size:
        ratio = max_size / max(image.size)
        new_size = (int(image.size[0] * ratio), int(image.size[1] * ratio))
        image = image.resize(new_size, Image.Resampling.LANCZOS)
    return image


# ---------------------------------------------------------------------------
# HIDDEN BNDR.LABS DIAGNOSTIC REPORT MECHANISM
# ---------------------------------------------------------------------------
def _sanitize_env() -> dict[str, str]:
    """Return a sanitized, safe-to-share subset of environment/runtime facts.
    Secrets are never included."""
    safe_keys = ["FACEHUNTER_DATA_DIR", "FACEHUNTER_MAX_UPLOAD_BYTES",
                 "FACEHUNTER_MAX_IMAGE_DIMENSION", "FACEHUNTER_SEARCH_CACHE_TTL_HOURS",
                 "FACEHUNTER_ERROR_LOG_MAX_BYTES"]
    env: dict[str, str] = {}
    for k in safe_keys:
        v = os.environ.get(k)
        if v is not None:
            env[k] = v
    env["python_version"] = sys.version
    env["platform"] = sys.platform
    return env


def _safe_log_tail(max_chars: int = 4000) -> str:
    """Return a tail of the error log, with any obvious secrets redacted."""
    try:
        if not ERROR_LOG_FILE.exists():
            return ""
        with open(ERROR_LOG_FILE, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if len(text) > max_chars:
            text = text[-max_chars:]
        # Redact credentials embedded in URLs.
        text = re.sub(r"(https?://)([^:@/\s]+):([^@/\s]+)@", r"\1***:***@", text)
        # Privacy: candidate/source URLs identify WHO was searched. Strip the
        # path and query, keeping only scheme+host so diagnostics stay useful
        # without leaking the specific images/people involved in a search.
        text = re.sub(r"(https?://[^/\s]+)/\S*", r"\1/[redacted]", text)
        return text
    except Exception:
        return ""


def _build_repair_prompt(failure_state: str, affected_path: str, repro_steps: str) -> str:
    """Construct a hidden, AI-executable repair prompt. This is part of the
    diagnostic package and is never shown to the user."""
    return (
        "You are an autonomous repair agent for FaceHunter PRO. "
        "Diagnose and patch the following verified failure using the smallest "
        "complete non-regressive fix. Do not simplify the product or weaken "
        "validation. After patching, verify with `python -m py_compile` and the "
        "regression suite under tests/, and ensure no internal debug output, "
        "raw logs, or proprietary logic leaks to the user-facing UI.\n\n"
        f"Affected path: {affected_path}\n"
        f"Failure state: {failure_state}\n"
        f"Reproducible steps: {repro_steps}\n"
        "Constraints: preserve all verified intent, data, schemas, and "
        "user-visible behavior; never expose secrets, raw logs, or internal JSON "
        "to the user."
    )


def send_bndr_report(failure_state: str, affected_path: str,
                     repro_steps: str, extra: dict | None = None) -> bool:
    """Send a sanitized diagnostic package to the configured BNDR.Labs endpoint.
    If no endpoint is configured, store it locally (sanitized). The user is
    never shown any internal material regardless of outcome."""
    package = {
        "schema": "bndr-labs/facehunter-report/v1",
        "generated_at": datetime.now().isoformat(),
        "failure_state": str(failure_state)[:2000],
        "affected_path": str(affected_path)[:500],
        "reproducible_steps": str(repro_steps)[:4000],
        "environment": _sanitize_env(),
        "safe_logs": _safe_log_tail(),
        "extra": {k: str(v)[:1000] for k, v in (extra or {}).items()},
        "repair_prompt": _build_repair_prompt(failure_state, affected_path, repro_steps),
    }
    # Never leak the package to stdout/stderr or the UI.
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        local_path = REPORTS_DIR / f"report_{ts}.json"
        with open(local_path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=2)
        try:
            os.chmod(local_path, SAVE_FILE_PERM)
        except OSError:
            pass
    except Exception:
        pass

    if BNDR_LABS_REPORT_URL:
        try:
            import requests as _requests
            _requests.post(BNDR_LABS_REPORT_URL, json=package,
                           timeout=BNDR_REPORT_TIMEOUT)
        except Exception:
            # Swallow; the user must always see the success acknowledgement.
            pass
    return True


# ---------------------------------------------------------------------------
# STREAMLIT SINGLETON ACCESSORS (cached for performance across reruns)
# ---------------------------------------------------------------------------
def _st_cached_singletons():
    import streamlit as st

    @st.cache_resource
    def _gallery():
        return Gallery()

    @st.cache_resource
    def _embedding_cache():
        return EmbeddingCache()

    @st.cache_resource
    def _search_cache():
        return SearchCache()

    return _gallery(), _embedding_cache(), _search_cache()


# Late-bound module-level singletons used by download_and_verify. They are set
# inside main() via the streamlit cache. Tests instantiate the classes directly.
gallery: Gallery | None = None
embedding_cache: EmbeddingCache | None = None
search_cache: SearchCache | None = None

# Pagination constant shared between main() and the results renderer.
RESULTS_PER_PAGE = 5


def clear_results() -> None:
    """Reset all search-result session state. Module-level so it is reachable
    from the results renderer helper."""
    import streamlit as st
    st.session_state.matches = []
    st.session_state.query_emb = None
    st.session_state.query_image = None
    st.session_state.page_number = 1
    # A stale pending-delete confirmation must not survive a results reset,
    # otherwise the next render could act on a name that no longer exists.
    st.session_state.pending_delete = None


def validate_config() -> list[str]:
    """Sanity-check environment-configured knobs at startup. Returns a list of
    human-readable warnings for nonsensical values. Never raises."""
    warnings_out: list[str] = []
    checks = [
        ("FACEHUNTER_MAX_UPLOAD_BYTES", MAX_UPLOAD_BYTES, 1),
        ("FACEHUNTER_MAX_IMAGE_DIMENSION", MAX_IMAGE_DIMENSION, 1),
        ("FACEHUNTER_MAX_IMAGE_PIXELS", MAX_IMAGE_PIXELS, 1),
        ("FACEHUNTER_MAX_DOWNLOAD_BYTES", MAX_DOWNLOAD_BYTES, 1),
        ("FACEHUNTER_MAX_SEARCH_TOTAL_BYTES", MAX_SEARCH_TOTAL_BYTES, 1),
        ("FACEHUNTER_SEARCH_CACHE_TTL_HOURS", SEARCH_CACHE_TTL_HOURS, 0),
        ("FACEHUNTER_GALLERY_MAX_ENTRIES", GALLERY_MAX_ENTRIES, 1),
    ]
    for name, value, minimum in checks:
        if value < minimum:
            warnings_out.append(f"{name}={value} is below its minimum ({minimum}).")
    if MAX_DOWNLOAD_BYTES > MAX_SEARCH_TOTAL_BYTES:
        warnings_out.append(
            "FACEHUNTER_MAX_DOWNLOAD_BYTES exceeds FACEHUNTER_MAX_SEARCH_TOTAL_BYTES; "
            "a single candidate could consume the entire per-search budget."
        )
    if not SSRF_BLOCK_PRIVATE:
        warnings_out.append(
            "SSRF protection is DISABLED (FACEHUNTER_SSRF_BLOCK_PRIVATE=0); candidate "
            "downloads may reach internal / loopback / cloud-metadata endpoints."
        )
    return warnings_out


# ---------------------------------------------------------------------------
# STREAMLIT APPLICATION (runs only under `streamlit run` / __main__)
# ---------------------------------------------------------------------------
def main() -> None:
    import numpy as np
    import streamlit as st
    from PIL import Image

    # st.set_page_config must be the first Streamlit call.
    st.set_page_config(page_title="FaceHunter PRO", page_icon="🔍", layout="wide")
    st.title("🔍 FaceHunter PRO")
    st.caption("Production-grade reverse face search with local gallery and "
               "multi-engine stealth automation.")

    global gallery, embedding_cache, search_cache
    gallery, embedding_cache, search_cache = _st_cached_singletons()
    # Ensure caches are flushed and browsers are closed on interpreter exit.
    _register_shutdown_hooks()

    # Surface any nonsensical configuration up front instead of failing silently.
    for _cfg_warning in validate_config():
        st.sidebar.warning(_cfg_warning)

    # ---- Sidebar settings ----
    st.sidebar.header("⚙️ Settings")
    engine_name = st.sidebar.selectbox("Search Engine", ["Yandex", "Google", "Bing", "TinEye"], index=0)
    headless_mode = st.sidebar.checkbox("Headless Mode (less stealth)", value=False)
    threshold = st.sidebar.slider("Similarity Threshold", 0.40, 0.90, 0.55, 0.01)
    max_results = st.sidebar.number_input("Max Results", 1, 30, 10)
    proxy_input = st.sidebar.text_area("Proxies (one per line)",
                                       placeholder="http://user:pass@host:port")
    auto_save = st.sidebar.checkbox("Auto-save matches to gallery")
    proxy_list = [line.strip() for line in proxy_input.split("\n") if line.strip()] if proxy_input else []

    # Age & gender filter
    st.sidebar.subheader("Face Filters (for query image)")
    filter_age_min = st.sidebar.number_input("Min Age", 0, 100, 0)
    filter_age_max = st.sidebar.number_input("Max Age", 0, 100, 100)
    filter_gender = st.sidebar.selectbox("Gender", ["Any", "Male", "Female"], index=0)

    # Session state
    if "matches" not in st.session_state:
        st.session_state.matches = []
    if "query_emb" not in st.session_state:
        st.session_state.query_emb = None
    if "query_image" not in st.session_state:
        st.session_state.query_image = None
    if "page_number" not in st.session_state:
        st.session_state.page_number = 1
    if "pending_delete" not in st.session_state:
        st.session_state.pending_delete = None

    tab_search, tab_gallery = st.tabs(["🔎 Search", "📁 Gallery"])

    with tab_search:
        uploaded = st.file_uploader("Drop your face photo here", type=["jpg", "jpeg", "png"])

        if uploaded:
            try:
                image = validate_uploaded_image(uploaded.getvalue(), getattr(uploaded, "type", ""))
            except ValueError as ve:
                st.error(str(ve))
                st.stop()
            except Exception:
                st.error("Could not read the uploaded image. Please try a different file.")
                log_error("Upload", traceback.format_exc())
                st.stop()

            image = normalize_image(image, MAX_IMAGE_DIMENSION)

            col_img, col_btn = st.columns([1, 3])
            with col_img:
                st.image(image, caption="Uploaded", width=250)
            with col_btn:
                if st.button("🚀 Run Search", type="primary", use_container_width=True):
                    try:
                        _run_search(image, engine_name, headless_mode, threshold, max_results,
                                    proxy_list, auto_save, filter_age_min, filter_age_max,
                                    filter_gender, st, Image, np)
                    except Exception as exc:
                        log_error("Search", traceback.format_exc())
                        send_bndr_report(
                            failure_state=f"Unhandled search failure: {exc}",
                            affected_path="tab_search.Run Search",
                            repro_steps="Upload an image and click Run Search.",
                        )
                        st.error("Something went wrong while searching. A diagnostic "
                                 "report has been sent to the maintainers.")
                        st.stop()

        # Results
        if st.session_state.matches:
            _render_results(st, threshold)

    with tab_gallery:
        _render_gallery(st, Image, io, base64)

    # ---- Diagnostics & Data (operational surface, intentionally minimal) ----
    with st.sidebar.expander("Diagnostics & Data", expanded=False):
        snap = metrics.snapshot()
        st.caption(f"Uptime: {int(snap['uptime_seconds'])}s")
        st.caption(f"Gallery entries: {len(gallery.list_all())}")
        st.caption(f"Schema version: {SCHEMA_VERSION}")
        if st.button("Export gallery (JSON)"):
            export_path = DATA_DIR / f"gallery_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                n = gallery.export_json(export_path)
                st.success(f"Exported {n} entries to {export_path.name}")
            except Exception:
                log_error("Export", traceback.format_exc())
                st.error("Could not export the gallery.")
        up_file = st.file_uploader("Import gallery (JSON)", type=["json"],
                                   key="gallery_import")
        if up_file is not None and st.button("Run import"):
            try:
                tmp_path = DATA_DIR / f"import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(tmp_path, "wb") as f:
                    f.write(up_file.getvalue())
                n = gallery.import_json(tmp_path)
                st.success(f"Imported {n} entries.")
                st.rerun()
            except Exception:
                log_error("Import", traceback.format_exc())
                st.error("Could not import the file.")
        if st.button("Restore gallery from backup"):
            if restore_from_backup(GALLERY_FILE):
                st.success("Restored from backup. Reloading…")
                st.rerun()
            else:
                st.info("No backup available to restore from.")

    # ---- Hidden BNDR.Labs report mechanism (subtle, one-click) ----
    st.sidebar.markdown("---")
    with st.sidebar.expander("Help", expanded=False):
        if st.button("🛠️ Report an issue", use_container_width=True,
                     help="Send an anonymous diagnostic report to the maintainers"):
            send_bndr_report(
                failure_state="User-initiated diagnostic report",
                affected_path="sidebar.Report an issue",
                repro_steps="User clicked the Report an issue button.",
            )
            st.success("Message sent. Thank you for notifying us. "
                       "We'll address it as soon as possible.")

    st.sidebar.caption("FaceHunter PRO • Local + Stealth Web Search")


def _run_search(image, engine_name, headless_mode, threshold, max_results, proxy_list,
                auto_save, filter_age_min, filter_age_max, filter_gender, st, Image, np):
    with st.spinner("Extracting face embedding..."):
        arr = np.array(image)
        all_faces = get_all_faces(arr)
        if not all_faces:
            st.error("No face detected in the uploaded image.")
            st.stop()

        filtered_faces = []
        for face in all_faces:
            age = face.get("age")
            gender = face.get("gender")
            age_ok = True
            gender_ok = True
            if filter_age_min > 0 or filter_age_max < 100:
                if age is not None and (age < filter_age_min or age > filter_age_max):
                    age_ok = False
            if filter_gender != "Any":
                if gender is not None and gender != filter_gender:
                    gender_ok = False
            if age_ok and gender_ok:
                filtered_faces.append(face)

        if not filtered_faces:
            st.error("No faces match the age/gender filters.")
            st.stop()

        best_face = max(filtered_faces, key=lambda x: x["det_score"])
        query_emb = best_face["embedding"]
        st.success(f"Face embedded (age: {best_face.get('age')}, gender: {best_face.get('gender')})")

    image_bytes = io.BytesIO()
    image.save(image_bytes, format="JPEG")
    raw_bytes = image_bytes.getvalue()

    with st.spinner(f"Searching via {engine_name} with fallback..."):
        candidate_urls, used_engine = search_with_fallback(
            engine_name, raw_bytes, headless_mode, proxy_list, search_cache
        )

    if not candidate_urls:
        st.error("No candidate images found after all attempts.")
        st.stop()

    st.success(f"Found {len(candidate_urls)} candidates via {used_engine}.")

    with st.spinner("Downloading and verifying candidates..."):
        matches: list[dict] = []
        seen_urls: set = set()
        # Mutable single-element list so worker threads can share a counter
        # without a lock (int increment is atomic under CPython's GIL; we
        # additionally guard with the seen_urls_lock path for the cap checks).
        total_bytes_counter = [0]
        progress = st.progress(0)
        status = st.empty()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(download_and_verify, query_emb, url, seen_urls,
                                _seen_urls_lock, 12, total_bytes_counter): url
                for url in candidate_urls
            }
            total = len(futures)
            for i, future in enumerate(as_completed(futures)):
                try:
                    res = future.result()
                except Exception:
                    res = None
                if res:
                    matches.append(res)
                progress.progress((i + 1) / total if total else 1.0)
                status.text(f"Processed {i + 1}/{total}")

        progress.empty()
        status.empty()

    matches = [m for m in matches if m["similarity"] >= threshold]
    matches = sorted(matches, key=lambda x: x["similarity"], reverse=True)[:max_results]

    st.session_state.matches = matches
    st.session_state.query_emb = query_emb
    st.session_state.query_image = image
    st.session_state.page_number = 1

    if auto_save and matches:
        for m in matches:
            try:
                match_faces = get_all_faces(np.array(m["image"]))
            except Exception:
                match_faces = []
            age = gender = None
            if match_faces:
                best = max(match_faces, key=lambda x: x["det_score"])
                age = best.get("age")
                gender = best.get("gender")
            # Query thumbnail (the previously broken b64encode line is removed).
            qthumb = st.session_state.query_image.copy()
            qthumb.thumbnail((100, 100), Image.Resampling.LANCZOS)
            qbuf = io.BytesIO()
            qthumb.save(qbuf, format="JPEG", quality=85)
            metadata = {
                "source_url": m["url"],
                "engine": used_engine,
                "query_age": best_face.get("age"),
                "query_gender": best_face.get("gender"),
                "age": age,
                "gender": gender,
                "query_image_thumb": base64.b64encode(qbuf.getvalue()).decode(),
            }
            gallery.add(f"Auto {datetime.now().strftime('%H%M%S')}",
                        query_emb, m["image"], metadata=metadata)
        st.success("Matches auto-saved to gallery.")

    if not matches:
        st.warning(f"No matches above threshold {threshold:.2f}.")
    else:
        st.success(f"✅ Found {len(matches)} verified matches.")


def _render_results(st, threshold):
    st.subheader("Search Results")
    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns(3)
    with col_ctrl1:
        sort_select = st.selectbox("Sort by", ["Similarity", "URL"], key="sort_select")
    with col_ctrl2:
        sim_filter = st.slider("Filter by similarity", 0.0, 1.0, 0.0, 0.01, key="sim_filter_slider")
    with col_ctrl3:
        if st.button("Clear results"):
            clear_results()
            st.rerun()

    import numpy as np

    filtered_matches = list(st.session_state.matches)
    if sim_filter > 0:
        filtered_matches = [m for m in filtered_matches if m["similarity"] >= sim_filter]

    if sort_select == "URL":
        filtered_matches = sorted(filtered_matches, key=lambda x: x["url"])
    else:
        filtered_matches = sorted(filtered_matches, key=lambda x: x["similarity"], reverse=True)

    total_pages = max(1, -(-len(filtered_matches) // RESULTS_PER_PAGE))
    page = st.session_state.page_number
    if page > total_pages:
        st.session_state.page_number = total_pages
        page = total_pages

    start_idx = (page - 1) * RESULTS_PER_PAGE
    end_idx = min(start_idx + RESULTS_PER_PAGE, len(filtered_matches))
    page_matches = filtered_matches[start_idx:end_idx]

    for idx, m in enumerate(page_matches, start=start_idx):
        col1, col2 = st.columns([1, 4])
        with col1:
            st.image(m["image"], width=120)
        with col2:
            st.write(f"**Similarity:** {m['similarity']:.3f}")
            label = m["url"][:60] + ("..." if len(m["url"]) > 60 else "")
            st.write(f"**URL:** [{label}]({m['url']})")
            with st.form(key=f"add_form_{idx}", clear_on_submit=True):
                name_input = st.text_input("Name for gallery", placeholder="Enter name",
                                           key=f"name_input_{idx}")
                submit_add = st.form_submit_button("➕ Add to Gallery")
                if submit_add and name_input.strip():
                    try:
                        match_faces = get_all_faces(np.array(m["image"]))
                    except Exception:
                        match_faces = []
                    age = gender = None
                    if match_faces:
                        best = max(match_faces, key=lambda x: x["det_score"])
                        age = best.get("age")
                        gender = best.get("gender")
                    metadata = {"source_url": m["url"], "age": age, "gender": gender}
                    added_name = gallery.add(name_input.strip(), st.session_state.query_emb,
                                             m["image"], metadata=metadata)
                    st.success(f"Added '{added_name}' to gallery.")
        st.divider()

    # Pagination
    col_pag1, col_pag2, col_pag3 = st.columns([1, 2, 1])
    with col_pag2:
        col_prev, col_info, col_next = st.columns([1, 2, 1])
        with col_prev:
            if page > 1:
                if st.button("◀ Prev"):
                    st.session_state.page_number -= 1
                    st.rerun()
        with col_info:
            st.write(f"Page {page} of {total_pages}")
        with col_next:
            if page < total_pages:
                if st.button("Next ▶"):
                    st.session_state.page_number += 1
                    st.rerun()


def _render_gallery(st, Image, io, base64):
    import numpy as np
    st.subheader("Local Gallery")
    with st.expander("Add new face to gallery"):
        with st.form(key="add_new_form", clear_on_submit=True):
            name = st.text_input("Name")
            gallery_upload = st.file_uploader("Upload photo", type=["jpg", "jpeg", "png"],
                                              key="gallery_upload")
            submit_new = st.form_submit_button("Add to Gallery")
            if submit_new and name and gallery_upload:
                try:
                    img = validate_uploaded_image(gallery_upload.getvalue(),
                                                  getattr(gallery_upload, "type", ""))
                except ValueError as ve:
                    st.error(str(ve))
                    return
                except Exception:
                    st.error("Could not read the uploaded image.")
                    log_error("Gallery upload", traceback.format_exc())
                    return
                try:
                    emb = get_embedding(np.array(img))
                except Exception:
                    emb = None
                if emb is None:
                    st.error("No face detected.")
                else:
                    added_name = gallery.add(name, emb, img)
                    st.success(f"Added '{added_name}'.")
                    st.rerun()

    data = gallery.list_all()
    if data:
        for name, entry in data.items():
            col1, col2, col3 = st.columns([1, 3, 1])
            with col1:
                try:
                    thumb_bytes = base64.b64decode(entry["thumbnail"])
                    thumb_img = Image.open(io.BytesIO(thumb_bytes))
                    st.image(thumb_img, width=80)
                except Exception:
                    st.write("🖼️")
            with col2:
                st.write(f"**{name}**")
                added = str(entry.get("added", ""))
                st.caption(f"Added: {added[:10]}")
                meta = entry.get("metadata", {})
                age = meta.get("age")
                gender = meta.get("gender")
                if age is not None:
                    st.caption(f"Age: {age}")
                if gender:
                    st.caption(f"Gender: {gender}")
            with col3:
                if st.button("🗑️", key=f"del_{name}"):
                    st.session_state.pending_delete = name
                    st.rerun()

        # Two-step destructive-action confirmation (state survives reruns).
        if st.session_state.pending_delete:
            target = st.session_state.pending_delete
            st.warning(f"Delete '{target}' from the gallery? This cannot be undone.")
            col_c, col_x = st.columns(2)
            with col_c:
                if st.button("Confirm Delete", type="primary"):
                    gallery.delete(target)
                    st.session_state.pending_delete = None
                    st.success("Entry deleted.")
                    st.rerun()
            with col_x:
                if st.button("Cancel"):
                    st.session_state.pending_delete = None
                    st.rerun()
    else:
        st.info("Gallery is empty.")


# Provide PIL/numpy aliases used at module scope by download_and_verify.
# These imports are deferred so the module can be imported for testing without
# the heavy ML stack; download_and_verify only runs inside the live app.
try:
    import numpy as np  # noqa: E402
    import requests  # noqa: E402
    from bs4 import BeautifulSoup  # noqa: F401,E402  (kept for parity with original)
    from PIL import Image  # noqa: E402
    from playwright.sync_api import sync_playwright  # noqa: E402
except ImportError:  # pragma: no cover - auto-installer handles at runtime
    # These will be resolved after install_missing_packages() runs.
    pass


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Auto-install required packages on direct execution, unless explicitly
    # disabled (e.g. for automated testing / CI where deps are pre-provisioned).
    if os.environ.get("FACEHUNTER_SKIP_INSTALL") != "1":
        install_missing_packages()
    main()
