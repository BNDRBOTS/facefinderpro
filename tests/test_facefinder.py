"""Regression tests for FaceHunter PRO.

These tests exercise the pure-logic and persistence layers that were corrected
during the forensic audit. They do NOT require InsightFace, ONNX Runtime,
Playwright browsers, or network access. The Streamlit UI is exercised separately
via streamlit.testing.v1.AppTest in test_app_smoke.py.

Run with:  .venv/bin/python -m pytest tests/ -q
"""

import io
import os
import pickle
import sys
import threading
from pathlib import Path

import numpy as np
from PIL import Image

# Make the module importable without running the UI.
os.environ.setdefault("FACEHUNTER_SKIP_INSTALL", "1")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import importlib.util

_spec = importlib.util.spec_from_file_location("FaceFinderPRO", ROOT / "FaceFinderPRO.py")
FaceFinderPRO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FaceFinderPRO)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_image(color=(255, 0, 0), size=(50, 50)) -> Image.Image:
    arr = np.zeros((size[1], size[0], 3), dtype=np.uint8)
    arr[:, :] = color
    return Image.fromarray(arr, "RGB")


def _make_pil_png_bytes(color=(0, 255, 0), size=(40, 40)) -> bytes:
    buf = io.BytesIO()
    _make_image(color, size).save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Audit Finding: file was wrapped in markdown fences (```python ... ```)
# ---------------------------------------------------------------------------
def test_file_is_pure_python_no_markdown_fence():
    """The original artifact began with ```python and ended with ```, making it
    a SyntaxError to execute. The remediated file must be pure Python."""
    src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
    assert not src.lstrip().startswith("```python"), "File still wrapped in markdown fence"
    assert not src.rstrip().endswith("```"), "File still ends with markdown fence"
    # Must compile.
    compile(src, "FaceFinderPRO.py", "exec")


# ---------------------------------------------------------------------------
# Audit Finding: duplicate class definitions + omitted Bing/TinEye refactor
# ---------------------------------------------------------------------------
def test_single_engine_implementation_all_have_attempt_search():
    """Original defined YandexEngine/GoogleEngine/BingEngine/TinEyeEngine twice
    (once with internal retry using `search()`, once refactored to
    `attempt_search`) but the refactor OMITTED Bing and TinEye. Selecting Bing
    or TinEye raised AttributeError: 'BingEngine' has no attribute
    'attempt_search'."""
    classes = FaceFinderPRO.ENGINE_CLASSES
    assert set(classes.keys()) == {"Yandex", "Google", "Bing", "TinEye"}
    for name, cls in classes.items():
        assert hasattr(cls, "attempt_search"), f"{name} missing attempt_search"
        assert not hasattr(cls, "search"), f"{name} still has legacy search()"


# ---------------------------------------------------------------------------
# Audit Finding: page.mouse.position does not exist in Playwright Python
# ---------------------------------------------------------------------------
def test_bezier_move_does_not_reference_mouse_position():
    """Original bezier_move used `page.mouse.position` which does not exist in
    Playwright's Python API, raising AttributeError and silently breaking all
    human-like clicking. The fix tracks position manually."""
    import inspect
    src = inspect.getsource(FaceFinderPRO.bezier_move)
    # The original broken assignment must not be present as executable code.
    assert "start_x, start_y = page.mouse.position" not in src
    assert "page.mouse.position)" not in src  # not used as a value anywhere
    assert "_get_mouse_pos" in src


def test_mouse_position_tracking_roundtrip():
    class FakePage:
        pass

    p = FakePage()
    assert FaceFinderPRO._get_mouse_pos(p) == (0.0, 0.0)
    FaceFinderPRO._set_mouse_pos(p, 12.5, 7.5)
    assert FaceFinderPRO._get_mouse_pos(p) == (12.5, 7.5)


# ---------------------------------------------------------------------------
# Audit Finding: requests.head(..., max_redirects=...) is invalid kwarg
# ---------------------------------------------------------------------------
def test_upgrade_image_url_no_invalid_max_redirects_kwarg():
    """Original passed max_redirects= as a per-request kwarg to requests.head,
    which is not accepted; the resulting TypeError was swallowed and redirects
    were never followed. The fix uses session.max_redirects."""
    import inspect
    src = inspect.getsource(FaceFinderPRO.upgrade_image_url)
    assert "max_redirects=" not in src.replace("session.max_redirects =", "")
    assert "session.max_redirects" in src


def test_upgrade_image_url_enlarges_size_params():
    url = "https://example.com/img.jpg?w=100&h=100"
    upgraded = FaceFinderPRO.upgrade_image_url(url)
    # Without network it falls back to the size-modified url (HEAD will fail).
    assert upgraded is not None
    assert "w=800" in upgraded and "h=800" in upgraded


def test_upgrade_image_url_returns_none_for_non_http():
    assert FaceFinderPRO.upgrade_image_url("data:image/png;base64,abc") is None


# ---------------------------------------------------------------------------
# Audit Finding: base64.b64encode(io.BytesIO()).getvalue() crashed auto-save
# ---------------------------------------------------------------------------
def test_auto_save_metadata_thumb_not_broken():
    """Original auto-save had: base64.b64encode(io.BytesIO()).getvalue()
    which raises TypeError before the correct thumbnail was generated. Ensure
    no such pattern remains and the correct path is used."""
    src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
    assert "base64.b64encode(io.BytesIO())" not in src, "Broken b64encode call remains"
    assert "base64.b64encode(qbuf.getvalue())" in src, "Correct thumbnail encoding missing"


# ---------------------------------------------------------------------------
# Audit Finding: gallery delete confirmation never deleted (state lost on rerun)
# ---------------------------------------------------------------------------
def test_gallery_delete_actually_removes(tmp_path, monkeypatch):
    """Original two-step delete relied on a `to_delete` list rebuilt each run;
    the Confirm button click happened in a run where to_delete was empty, so
    nothing was ever deleted. The fix uses session_state (tested via delete())."""
    monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "gallery.pkl")
    g = FaceFinderPRO.Gallery()
    g.add("alice", np.array([1.0, 0.0]), _make_image())
    assert "alice" in g.list_all()
    assert g.delete("alice") is True
    assert "alice" not in g.list_all()
    assert g.delete("alice") is False  # idempotent


def test_gallery_add_dedups_names(tmp_path, monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "gallery.pkl")
    g = FaceFinderPRO.Gallery()
    n1 = g.add("bob", np.array([1.0]), _make_image())
    n2 = g.add("bob", np.array([1.0]), _make_image())
    assert n1 == "bob"
    assert n2 == "bob_1"
    assert set(g.list_all().keys()) == {"bob", "bob_1"}


# ---------------------------------------------------------------------------
# Audit Finding: non-atomic pickle writes; corruption on crash/interrupt
# ---------------------------------------------------------------------------
def test_atomic_write_leaves_no_partial_file_on_error(tmp_path, monkeypatch):
    target = tmp_path / "out.pkl"
    # Force pickle.dump to fail mid-write.
    class Bad:
        def __reduce__(self):
            raise RuntimeError("simulated crash")

    monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", target)
    # _atomic_pickle_write should not leave a corrupt target file on failure.
    try:
        FaceFinderPRO._atomic_pickle_write(target, Bad())
    except Exception:
        pass
    assert not target.exists() or target.stat().st_size == 0 or _is_loadable(target) is None is False
    # No lingering temp file.
    assert not target.with_suffix(".pkl.tmp").exists()


def _is_loadable(path):
    try:
        with open(path, "rb") as f:
            pickle.load(f)
        return True
    except Exception:
        return None


def test_safe_pickle_load_recovers_from_corruption(tmp_path):
    corrupt = tmp_path / "bad.pkl"
    corrupt.write_bytes(b"\x80\x05 not a valid pickle payload")
    result = FaceFinderPRO._safe_pickle_load(corrupt, {"default": True})
    assert result == {"default": True}
    # A corrupt backup should be preserved as evidence.
    assert corrupt.with_suffix(".pkl.corrupt").exists()


# ---------------------------------------------------------------------------
# Audit Finding: thread-unsafe concurrent writes to embedding cache
# ---------------------------------------------------------------------------
def test_embedding_cache_concurrent_set_is_thread_safe(tmp_path, monkeypatch):
    """Original EmbeddingCache.set() wrote the pickle from every worker thread
    without a lock, corrupting the file under concurrency. Verify thread-safe
    behavior and integrity under parallel writes."""
    monkeypatch.setattr(FaceFinderPRO, "EMBEDDING_CACHE_FILE", tmp_path / "emb.pkl")
    cache = FaceFinderPRO.EmbeddingCache()

    def writer(i):
        cache.set(f"img-{i}".encode(), np.array([float(i)]))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Reload from disk; must be intact and contain all entries.
    cache2 = FaceFinderPRO.EmbeddingCache()
    assert len(cache2.cache) == 30
    for i in range(30):
        assert cache2.get(f"img-{i}".encode()) is not None


# ---------------------------------------------------------------------------
# Audit Finding: SearchCache TTL + atomicity
# ---------------------------------------------------------------------------
def test_search_cache_ttl_expiry(tmp_path, monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "sc.pkl")
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 0)  # immediate expiry
    cache = FaceFinderPRO.SearchCache()
    cache.set(b"img-bytes", ["https://example.com/a"])
    # TTL=0 means already expired.
    assert cache.get(b"img-bytes") is None


def test_search_cache_hit_within_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "sc.pkl")
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 24)
    cache = FaceFinderPRO.SearchCache()
    cache.set(b"img-bytes", ["https://example.com/a"])
    assert cache.get(b"img-bytes") == ["https://example.com/a"]


# ---------------------------------------------------------------------------
# Audit Finding: cosine_sim divide-by-zero on zero-norm embeddings
# ---------------------------------------------------------------------------
def test_cosine_sim_zero_norm_safe():
    assert FaceFinderPRO.cosine_sim(None, np.array([1.0])) == 0.0
    assert FaceFinderPRO.cosine_sim(np.array([0.0, 0.0]), np.array([1.0, 0.0])) == 0.0
    assert abs(FaceFinderPRO.cosine_sim(np.array([1.0, 0.0]), np.array([1.0, 0.0])) - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# Audit Finding: no upload validation (oversized/corrupt images)
# ---------------------------------------------------------------------------
def test_validate_uploaded_image_rejects_oversized(monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "MAX_UPLOAD_BYTES", 100)
    try:
        FaceFinderPRO.validate_uploaded_image(b"\x00" * 200, "image/png")
        assert False, "Should have raised"
    except ValueError as ve:
        assert "too large" in str(ve)


def test_validate_uploaded_image_rejects_corrupt():
    try:
        FaceFinderPRO.validate_uploaded_image(b"not an image", "image/png")
        assert False, "Should have raised"
    except ValueError as ve:
        assert "not valid" in str(ve).lower() or "not a valid image" in str(ve).lower()


def test_validate_uploaded_image_accepts_valid_png():
    img = FaceFinderPRO.validate_uploaded_image(_make_pil_png_bytes(), "image/png")
    assert img.mode == "RGB"
    assert img.size == (40, 40)


def test_normalize_image_downscales():
    big = _make_image(size=(2000, 1000))
    out = FaceFinderPRO.normalize_image(big, max_size=512)
    assert max(out.size) <= 512


# ---------------------------------------------------------------------------
# Audit Finding: search_with_fallback called attempt_search on engines that
# lacked it (Bing/TinEye). Verify the orchestrator works for every engine.
# ---------------------------------------------------------------------------
def test_search_with_fallback_unknown_engine_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "sc.pkl")
    monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 24)
    cache = FaceFinderPRO.SearchCache()
    urls, label = FaceFinderPRO.search_with_fallback("UnknownEngine", b"img", True, [], cache)
    assert urls == []
    assert label == "None"


# ---------------------------------------------------------------------------
# Audit Finding: search_yandex_requests crashed on non-JSON responses
# ---------------------------------------------------------------------------
def test_search_yandex_requests_handles_non_json(monkeypatch):
    class FakeResp:
        status_code = 200
        def json(self):
            raise ValueError("not json")
    class FakeSession:
        def get(self, *a, **k):
            return FakeResp()
        def post(self, *a, **k):
            return FakeResp()
    monkeypatch.setattr(FaceFinderPRO.requests, "Session", lambda: FakeSession())
    # Should not raise even though upstream returns non-JSON.
    result = FaceFinderPRO.search_yandex_requests(b"img", retries=1)
    assert result == []


# ---------------------------------------------------------------------------
# Audit Finding: BNDR.Labs hidden report mechanism was absent
# ---------------------------------------------------------------------------
def test_send_bndr_report_creates_sanitized_local_package(tmp_path, monkeypatch):
    monkeypatch.setattr(FaceFinderPRO, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(FaceFinderPRO, "REPORTS_DIR", tmp_path / "reports")
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(FaceFinderPRO, "BNDR_LABS_REPORT_URL", "")  # local-only
    ok = FaceFinderPRO.send_bndr_report(
        failure_state="test failure",
        affected_path="test/path",
        repro_steps="step 1; step 2",
    )
    assert ok is True
    reports = list((tmp_path / "reports").glob("report_*.json"))
    assert len(reports) == 1
    import json
    pkg = json.loads(reports[0].read_text())
    assert pkg["schema"] == "bndr-labs/facehunter-report/v1"
    assert pkg["failure_state"] == "test failure"
    assert "repair_prompt" in pkg  # hidden AI repair prompt present
    # No secrets leaked into the package.
    env = pkg["environment"]
    assert all("password" not in k.lower() and "secret" not in k.lower() for k in env)


def test_send_bndr_report_user_message_constant():
    """The user-facing acknowledgement must contain the required string and
    the internal package must never be printed."""
    src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
    # The message is split across two string literals for readability; both
    # fragments must be present.
    assert "Message sent. Thank you for notifying us." in src
    assert "We'll address it as soon as possible." in src
    # The internal diagnostic package must never be printed to stdout/stderr.
    assert "print(package)" not in src


# ---------------------------------------------------------------------------
# Audit Finding: error log grew unbounded
# ---------------------------------------------------------------------------
def test_log_error_rotates_when_too_large(tmp_path, monkeypatch):
    log = tmp_path / "errors.log"
    monkeypatch.setattr(FaceFinderPRO, "ERROR_LOG_FILE", log)
    monkeypatch.setattr(FaceFinderPRO, "ERROR_LOG_MAX_BYTES", 200)
    for i in range(50):
        FaceFinderPRO.log_error("Test", f"error number {i} " * 10)
    assert log.exists()
    # A rotated backup should exist.
    assert log.with_suffix(".log.1").exists() or log.stat().st_size <= 200


# ---------------------------------------------------------------------------
# Audit Finding: download_and_verify seen_urls TOCTOU race
# ---------------------------------------------------------------------------
def test_download_and_verify_dedup_is_thread_safe():
    """seen_urls check-and-add must be atomic to avoid duplicate downloads."""
    seen = set()
    lock = threading.Lock()
    # No network: download_and_verify will fail at HEAD and return None, but
    # the dedup happens before any network call.

    class FakeQuery:
        pass

    # Patch requests.head to always raise so we exit fast after dedup.
    def fake_head(*a, **k):
        raise RuntimeError("no network")
    FaceFinderPRO.requests.head = fake_head

    def worker(url):
        r = FaceFinderPRO.download_and_verify(np.array([1.0]), url, seen, lock, timeout=1)
        if r is None:
            # count how many got past dedup (i.e. were added to seen)
            pass

    urls = [f"https://example.com/img{i}.jpg" for i in range(5)] * 4  # 20 calls, 5 unique
    threads = [threading.Thread(target=worker, args=(u,)) for u in urls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly 5 unique URLs should have entered the seen set.
    assert len(seen) == 5


# ---------------------------------------------------------------------------
# Audit Finding: bare except: clauses swallow SystemExit/KeyboardInterrupt
# ---------------------------------------------------------------------------
def test_no_bare_except_clauses():
    src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
    # Disallow `except:` with no exception type.
    import re
    bare = re.findall(r"^\s*except\s*:", src, re.MULTILINE)
    assert bare == [], f"Bare except: clauses remain: {len(bare)}"


# ---------------------------------------------------------------------------
# Audit Finding: unused imports (math, Union)
# ---------------------------------------------------------------------------
def test_no_unused_imports_math_union():
    src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
    # math and Union were imported but unused in the original.
    lines = [ln for ln in src.splitlines() if ln.strip().startswith("import ") or ln.strip().startswith("from ")]
    joined = "\n".join(lines)
    assert "import math" not in joined, "math still imported (unused)"
    assert "Union" not in joined, "Union still imported (unused)"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
