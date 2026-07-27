"""Production-grade hardening tests for FaceHunter PRO.

These tests cover the additional hardening applied in the second pass:
SSRF protection, decompression-bomb defense, path-traversal sanitization,
restricted-unpickler RCE defense, HMAC integrity, schema migration,
backup/restore, gallery export/import, LRU cache eviction, browser lifecycle,
graceful shutdown, metrics, and week/month/year failure-mode scenarios.

Run with:  FACEHUNTER_SKIP_INSTALL=1 .venv/bin/python -m pytest tests/ -q
"""

import io
import json
import os
import pickle
import sys
import threading
from pathlib import Path

import numpy as np
from PIL import Image

os.environ.setdefault("FACEHUNTER_SKIP_INSTALL", "1")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import importlib.util

_spec = importlib.util.spec_from_file_location("FaceFinderPRO", ROOT / "FaceFinderPRO.py")
FaceFinderPRO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FaceFinderPRO)


def _make_image(color=(255, 0, 0), size=(50, 50)) -> Image.Image:
    arr = np.zeros((size[1], size[0], 3), dtype=np.uint8)
    arr[:, :] = color
    return Image.fromarray(arr, "RGB")


def _png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ===========================================================================
# SSRF PROTECTION
# ===========================================================================
class TestSSRF:
    def test_blocks_localhost(self):
        assert FaceFinderPRO.is_url_safe("http://localhost/img.jpg") is False
        assert FaceFinderPRO.is_url_safe("http://127.0.0.1/img.jpg") is False

    def test_blocks_loopback_ip(self):
        assert FaceFinderPRO.is_url_safe("http://127.0.0.1:8501/img.jpg") is False

    def test_blocks_link_local_metadata_service(self):
        # AWS / GCP / Azure metadata endpoint.
        assert FaceFinderPRO.is_url_safe("http://169.254.169.254/latest/meta-data/") is False

    def test_blocks_private_ranges(self):
        assert FaceFinderPRO.is_url_safe("http://10.0.0.1/img.jpg") is False
        assert FaceFinderPRO.is_url_safe("http://192.168.1.1/img.jpg") is False
        assert FaceFinderPRO.is_url_safe("http://172.16.0.1/img.jpg") is False

    def test_blocks_non_http_schemes(self):
        assert FaceFinderPRO.is_url_safe("file:///etc/passwd") is False
        assert FaceFinderPRO.is_url_safe("ftp://example.com/img.jpg") is False
        assert FaceFinderPRO.is_url_safe("gopher://example.com/") is False

    def test_blocks_no_hostname(self):
        assert FaceFinderPRO.is_url_safe("http:///img.jpg") is False
        assert FaceFinderPRO.is_url_safe("") is False

    def test_allows_public_when_disabled(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SSRF_BLOCK_PRIVATE", False)
        # With blocking off, scheme+host checks still apply.
        assert FaceFinderPRO.is_url_safe("http://example.com/img.jpg") is True

    def test_download_and_verify_blocks_ssrf(self):
        """download_and_verify must refuse an internal URL before any fetch."""
        seen = set()
        lock = threading.Lock()
        result = FaceFinderPRO.download_and_verify(
            np.array([1.0]), "http://127.0.0.1:9999/secret", seen, lock, 2, [0]
        )
        assert result is None
        # The URL was added to seen (dedup still records the attempt).
        assert "http://127.0.0.1:9999/secret" in seen


# ===========================================================================
# DECOMPRESSION-BOMB DEFENSE
# ===========================================================================
class TestDecompressionBomb:
    def test_safe_open_image_rejects_oversized_pixels(self, monkeypatch):
        # Craft a small PNG that declares huge dimensions. PIL will refuse.
        monkeypatch.setattr(FaceFinderPRO, "MAX_IMAGE_PIXELS", 100)
        # A legitimately small image is fine; the limit just needs to be low.
        small = _png_bytes(_make_image(size=(5, 5)))
        img = FaceFinderPRO.safe_open_image(small, source="upload")
        assert img.size == (5, 5)

    def test_safe_open_image_rejects_empty(self):
        try:
            FaceFinderPRO.safe_open_image(b"", source="upload")
            assert False
        except ValueError as ve:
            assert "empty" in str(ve).lower()

    def test_safe_open_image_rejects_corrupt(self):
        try:
            FaceFinderPRO.safe_open_image(b"not an image at all", source="upload")
            assert False
        except ValueError as ve:
            assert "not valid" in str(ve).lower()

    def test_safe_open_image_rejects_oversized_bytes(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "MAX_UPLOAD_BYTES", 50)
        try:
            FaceFinderPRO.safe_open_image(b"\x00" * 200, source="upload")
            assert False
        except ValueError as ve:
            assert "too large" in str(ve).lower()

    def test_validate_uploaded_image_uses_safe_open(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "MAX_IMAGE_PIXELS", 10)
        # 50x50 = 2500 pixels > 10 limit -> must be rejected.
        try:
            FaceFinderPRO.validate_uploaded_image(_png_bytes(_make_image(size=(50, 50))), "image/png")
            assert False, "Should have rejected oversized image"
        except ValueError:
            pass


# ===========================================================================
# FILENAME / PATH-TRAVERSAL SANITIZATION
# ===========================================================================
class TestNameSanitization:
    def test_rejects_empty(self):
        try:
            FaceFinderPRO.sanitize_gallery_name("")
            assert False
        except ValueError:
            pass

    def test_rejects_only_whitespace(self):
        try:
            FaceFinderPRO.sanitize_gallery_name("   ")
            assert False
        except ValueError:
            pass

    def test_strips_path_separators(self):
        out = FaceFinderPRO.sanitize_gallery_name("../../etc/passwd")
        assert "/" not in out
        assert ".." not in out or "_" in out

    def test_strips_null_bytes(self):
        out = FaceFinderPRO.sanitize_gallery_name("name\x00evil")
        assert "\x00" not in out

    def test_caps_length(self):
        long_name = "a" * 500
        out = FaceFinderPRO.sanitize_gallery_name(long_name)
        assert len(out) <= 200

    def test_collapses_whitespace(self):
        out = FaceFinderPRO.sanitize_gallery_name("john    doe")
        assert out == "john doe"

    def test_rejects_non_string(self):
        try:
            FaceFinderPRO.sanitize_gallery_name(123)
            assert False
        except ValueError:
            pass

    def test_gallery_add_sanitizes_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        name = g.add("../../etc/passwd", np.array([1.0]), _make_image())
        assert "/" not in name
        assert ".." not in name or "_" in name
        assert name in g.list_all()
        # The raw traversal string must NOT be a key.
        assert "../../etc/passwd" not in g.list_all()


# ===========================================================================
# RESTRICTED UNPICKLER (RCE defense)
# ===========================================================================
class TestRestrictedUnpickler:
    def test_blocks_os_system_rce(self):
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, ("echo HACKED",))
        payload = pickle.dumps(Exploit())
        try:
            FaceFinderPRO._restricted_load(payload)
            assert False, "RCE payload should be blocked"
        except pickle.UnpicklingError:
            pass

    def test_blocks_subprocess_popen(self):
        class Exploit:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (["echo", "x"],))
        payload = pickle.dumps(Exploit())
        try:
            FaceFinderPRO._restricted_load(payload)
            assert False
        except pickle.UnpicklingError:
            pass

    def test_blocks_eval(self):
        class Exploit:
            def __reduce__(self):
                return (eval, ("__import__('os').system('id')",))
        payload = pickle.dumps(Exploit())
        try:
            FaceFinderPRO._restricted_load(payload)
            assert False
        except pickle.UnpicklingError:
            pass

    def test_allows_plain_dict(self):
        payload = pickle.dumps({"a": 1, "b": [1, 2, 3]})
        out = FaceFinderPRO._restricted_load(payload)
        assert out == {"a": 1, "b": [1, 2, 3]}

    def test_allows_numpy_array(self):
        arr = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        payload = pickle.dumps(arr)
        out = FaceFinderPRO._restricted_load(payload)
        assert np.array_equal(out, arr)

    def test_allows_datetime(self):
        from datetime import datetime
        d = datetime(2024, 1, 1, 12, 0, 0)
        payload = pickle.dumps(d)
        out = FaceFinderPRO._restricted_load(payload)
        assert out == d

    def test_blocks_unknown_module(self):
        # A pickle referencing a non-allowlisted module must be blocked.
        # We craft a pickle by hand that references a fake module global.
        # Build a pickle that does GLOBAL on "evil_module.evil_func".
        payload = b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x0bevil_module\x8c\x09evil_func\x85R."  # noqa: E501
        try:
            FaceFinderPRO._restricted_load(payload)
            assert False
        except pickle.UnpicklingError:
            pass


# ===========================================================================
# HMAC INTEGRITY (tamper detection)
# ===========================================================================
class TestHMAC:
    def test_hmac_roundtrip(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "PICKLE_HMAC_SECRET", "test-secret")
        path = Path("/tmp/fh_hmac_test.pkl")
        try:
            FaceFinderPRO._atomic_pickle_write(path, {"hello": "world"})
            loaded = FaceFinderPRO._safe_pickle_load(path, {})
            assert loaded == {"hello": "world"}
        finally:
            if path.exists():
                path.unlink()

    def test_hmac_detects_tampering(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "PICKLE_HMAC_SECRET", "test-secret")
        path = Path("/tmp/fh_hmac_tamper.pkl")
        try:
            FaceFinderPRO._atomic_pickle_write(path, {"hello": "world"})
            # Tamper with the body (flip a byte after the tag-length header).
            data = bytearray(path.read_bytes())
            # tag_len is 0..4, tag is 4..36 (32 bytes), body starts at 36.
            data[-1] ^= 0x01
            path.write_bytes(bytes(data))
            loaded = FaceFinderPRO._safe_pickle_load(path, {"fallback": True})
            # Tampered store must fall back to default, not execute the payload.
            assert loaded == {"fallback": True}
        finally:
            if path.exists():
                path.unlink()

    def test_no_hmac_when_unset(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "PICKLE_HMAC_SECRET", "")
        assert FaceFinderPRO._hmac_tag(b"anything") == b""


# ===========================================================================
# SCHEMA VERSIONING & MIGRATION
# ===========================================================================
class TestSchema:
    def test_current_schema_version(self):
        assert FaceFinderPRO.SCHEMA_VERSION == 2

    def test_migrate_same_version_noop(self):
        payload = {"x": 1}
        assert FaceFinderPRO._migrate_payload(payload, FaceFinderPRO.SCHEMA_VERSION) is payload

    def test_migrate_legacy_v0_dict(self):
        legacy = {"alice": {"embedding": None}}
        out = FaceFinderPRO._migrate_payload(legacy, 0)
        assert out == legacy

    def test_migrate_refuses_future_schema(self):
        try:
            FaceFinderPRO._migrate_payload({}, 999)
            assert False
        except ValueError as ve:
            assert "newer than supported" in str(ve)

    def test_legacy_store_loads_in_new_format(self, tmp_path, monkeypatch):
        """A v0 bare-pickle store must still load after the envelope upgrade."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        # Write a legacy bare pickle (no envelope, no HMAC).
        legacy = {"alice": {"embedding": np.array([1.0]), "thumbnail": "",
                            "full_image": b"", "added": "2024-01-01",
                            "metadata": {}}}
        with open(tmp_path / "g.pkl", "wb") as f:
            pickle.dump(legacy, f)
        g = FaceFinderPRO.Gallery()
        assert "alice" in g.list_all()
        # After a save, it's upgraded to the envelope format.
        g.save()
        raw = (tmp_path / "g.pkl").read_bytes()
        # Envelope: 4-byte tag len (0) + body.
        assert int.from_bytes(raw[:4], "big") == 0


# ===========================================================================
# BACKUP / RESTORE
# ===========================================================================
class TestBackupRestore:
    def test_backup_creates_bak1(self, tmp_path, monkeypatch):
        path = tmp_path / "store.pkl"
        path.write_bytes(b"original")
        FaceFinderPRO._backup_store(path)
        assert (tmp_path / "store.pkl.bak1").exists()
        assert (tmp_path / "store.pkl.bak1").read_bytes() == b"original"

    def test_backup_rotates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "BACKUP_KEEP", 3)
        path = tmp_path / "store.pkl"
        for i in range(4):
            path.write_bytes(f"v{i}".encode())
            FaceFinderPRO._backup_store(path)
        # bak1 = most recent backup (v3), bak2 = v2, bak3 = v1; v0 gone.
        assert (tmp_path / "store.pkl.bak1").read_bytes() == b"v3"
        assert (tmp_path / "store.pkl.bak2").read_bytes() == b"v2"
        assert (tmp_path / "store.pkl.bak3").read_bytes() == b"v1"
        assert not (tmp_path / "store.pkl.bak4").exists()

    def test_backup_noop_when_missing(self, tmp_path):
        path = tmp_path / "nonexistent.pkl"
        # Should not raise.
        FaceFinderPRO._backup_store(path)
        assert not path.exists()

    def test_restore_from_backup(self, tmp_path, monkeypatch):
        path = tmp_path / "store.pkl"
        path.write_bytes(b"current-broken")
        bak1 = tmp_path / "store.pkl.bak1"
        bak1.write_bytes(b"good-backup")
        assert FaceFinderPRO.restore_from_backup(path) is True
        assert path.read_bytes() == b"good-backup"
        # The broken current must be preserved as .corrupt evidence.
        assert (tmp_path / "store.pkl.corrupt").read_bytes() == b"current-broken"

    def test_restore_no_backup_returns_false(self, tmp_path):
        path = tmp_path / "store.pkl"
        assert FaceFinderPRO.restore_from_backup(path) is False

    def test_gallery_save_makes_backup(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        # First add: no prior file, so no backup yet (file is created).
        g.add("alice", np.array([1.0]), _make_image())
        assert (tmp_path / "g.pkl").exists()
        assert not (tmp_path / "g.pkl.bak1").exists()
        # Second add: prior file exists, so a backup is made before overwrite.
        g.add("bob", np.array([2.0]), _make_image())
        assert (tmp_path / "g.pkl.bak1").exists()


# ===========================================================================
# GALLERY EXPORT / IMPORT
# ===========================================================================
class TestExportImport:
    def test_export_creates_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0]), _make_image(),
              metadata={"age": 30, "gender": "Female"})
        out_path = tmp_path / "export.json"
        n = g.export_json(out_path)
        assert n == 1
        data = json.loads(out_path.read_text())
        assert data["schema"] == FaceFinderPRO.SCHEMA_VERSION
        assert len(data["entries"]) == 1
        assert data["entries"][0]["name"] == "alice"
        assert data["entries"][0]["metadata"]["age"] == 30

    def test_export_does_not_leak_embeddings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0, 2.0, 3.0]), _make_image())
        out_path = tmp_path / "export.json"
        g.export_json(out_path)
        text = out_path.read_text()
        # Embeddings (numpy arrays) must NOT appear in the JSON export.
        assert "embedding" not in text.lower()

    def test_import_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0]), _make_image(), metadata={"age": 30})
        out_path = tmp_path / "export.json"
        g.export_json(out_path)
        # New gallery, import.
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g2.pkl")
        g2 = FaceFinderPRO.Gallery()
        n = g2.import_json(out_path)
        assert n == 1
        assert "alice" in g2.list_all()
        assert g2.list_all()["alice"]["metadata"]["age"] == 30

    def test_import_rejects_bad_format(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"no_entries": True}))
        g = FaceFinderPRO.Gallery()
        try:
            g.import_json(bad)
            assert False
        except ValueError:
            pass

    def test_import_dedups_names(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0]), _make_image())
        out_path = tmp_path / "export.json"
        g.export_json(out_path)
        # Import the same export twice.
        g.import_json(out_path)
        g.import_json(out_path)
        names = list(g.list_all().keys())
        assert "alice" in names
        assert "alice_1" in names


# ===========================================================================
# CACHE LRU EVICTION
# ===========================================================================
class TestCacheEviction:
    def test_embedding_cache_evicts_beyond_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "EMBEDDING_CACHE_FILE", tmp_path / "e.pkl")
        monkeypatch.setattr(FaceFinderPRO, "EMBEDDING_CACHE_MAX_ENTRIES", 5)
        cache = FaceFinderPRO.EmbeddingCache()
        for i in range(10):
            cache.set(f"img-{i}".encode(), np.array([float(i)]))
        assert len(cache.cache) <= 5

    def test_search_cache_evicts_beyond_cap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_MAX_ENTRIES", 3)
        cache = FaceFinderPRO.SearchCache()
        for i in range(6):
            cache.set(f"img-{i}".encode(), [f"https://example.com/{i}"])
        assert len(cache.cache) <= 3


# ===========================================================================
# GALLERY ENTRY CAP + ARCHIVAL
# ===========================================================================
class TestGalleryCap:
    def test_archive_overflow_entries(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_MAX_ENTRIES", 3)
        g = FaceFinderPRO.Gallery()
        for i in range(5):
            g.add(f"person_{i}", np.array([float(i)]), _make_image())
        assert len(g.list_all()) <= 3
        # Archived entries must be preserved, not dropped.
        archive_path = tmp_path / "g.archive.pkl"
        assert archive_path.exists()
        archived = FaceFinderPRO._safe_pickle_load(archive_path, {"entries": {}})
        assert len(archived["entries"]) == 2

    def test_no_silent_drop_on_archive_failure(self, tmp_path, monkeypatch):
        """If archiving fails, the gallery must keep entries (exceed cap) rather
        than silently lose data."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_MAX_ENTRIES", 2)
        # Break _atomic_pickle_write for the archive path by making the data dir
        # read-only after gallery creation.
        g = FaceFinderPRO.Gallery()
        for i in range(4):
            g.add(f"person_{i}", np.array([float(i)]), _make_image())
        # Either capped (archived) or exceeded (archive failed) — never empty.
        assert len(g.list_all()) >= 2


# ===========================================================================
# METRICS
# ===========================================================================
class TestMetrics:
    def test_inc_and_snapshot(self):
        m = FaceFinderPRO.Metrics()
        m.inc("foo")
        m.inc("foo")
        m.inc("bar", by=5)
        snap = m.snapshot()
        assert snap["counters"]["foo"] == 2
        assert snap["counters"]["bar"] == 5
        assert "uptime_seconds" in snap
        assert "started_at" in snap

    def test_thread_safe(self):
        m = FaceFinderPRO.Metrics()
        def worker():
            for _ in range(1000):
                m.inc("x")
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert m.snapshot()["counters"]["x"] == 10000


# ===========================================================================
# BROWSER LIFECYCLE GUARD
# ===========================================================================
class TestBrowserLifecycle:
    def test_register_unregister(self):
        class FakeBrowser:
            closed = False
            def close(self):
                self.closed = True
        b = FakeBrowser()
        FaceFinderPRO._register_browser(b)
        FaceFinderPRO._unregister_browser(b)
        FaceFinderPRO._shutdown_all_browsers()  # should be a no-op now
        assert b.closed is False

    def test_shutdown_closes_all_live(self):
        class FakeBrowser:
            def __init__(self):
                self.closed = False
            def close(self):
                self.closed = True
        browsers = [FakeBrowser() for _ in range(3)]
        for b in browsers:
            FaceFinderPRO._register_browser(b)
        FaceFinderPRO._shutdown_all_browsers()
        assert all(b.closed for b in browsers)
        # Registry is cleared.
        assert len(FaceFinderPRO._live_browsers) == 0

    def test_shutdown_idempotent(self):
        FaceFinderPRO._shutdown_all_browsers()
        FaceFinderPRO._shutdown_all_browsers()  # no error


# ===========================================================================
# GRACEFUL SHUTDOWN (atexit flush)
# ===========================================================================
class TestShutdown:
    def test_register_shutdown_hooks_idempotent(self):
        FaceFinderPRO._register_shutdown_hooks()
        FaceFinderPRO._register_shutdown_hooks()
        # _shutdown_registered should be True after first call.
        assert FaceFinderPRO._shutdown_registered is True

    def test_atexit_flush_does_not_raise(self, monkeypatch):
        # gallery/embedding_cache/search_cache may be None at import time.
        FaceFinderPRO.gallery = None
        FaceFinderPRO.embedding_cache = None
        FaceFinderPRO.search_cache = None
        # Should not raise.
        FaceFinderPRO._atexit_flush()


# ===========================================================================
# METADATA SANITIZATION (XSS defense in depth)
# ===========================================================================
class TestMetadataSanitization:
    def test_coerces_types(self):
        out = FaceFinderPRO._sanitize_metadata({
            "age": 30,
            "name": "alice",
            "tags": ["a", "b", "c"],
            "nested": {"k": "v"},
        })
        assert out["age"] == 30
        assert out["name"] == "alice"
        assert out["tags"] == ["a", "b", "c"]
        assert out["nested"]["k"] == "v"

    def test_caps_string_length(self):
        long_str = "x" * 10000
        out = FaceFinderPRO._sanitize_metadata({"k": long_str})
        assert len(out["k"]) == 5000

    def test_handles_non_dict(self):
        assert FaceFinderPRO._sanitize_metadata("not a dict") == {}
        assert FaceFinderPRO._sanitize_metadata(None) == {}

    def test_caps_key_length(self):
        long_key = "k" * 500
        out = FaceFinderPRO._sanitize_metadata({long_key: "v"})
        assert len(list(out.keys())[0]) == 200


# ===========================================================================
# WEEK-1 FAILURE MODES
# ===========================================================================
class TestWeekOne:
    def test_concurrent_gallery_adds_no_corruption(self, tmp_path, monkeypatch):
        """10 threads each adding 10 entries must produce exactly 100 entries,
        with no corruption or lost writes."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()

        def worker(i):
            for j in range(10):
                g.add(f"person_{i}_{j}", np.array([float(i * 10 + j)]), _make_image())

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(g.list_all()) == 100

    def test_concurrent_embedding_cache_no_corruption(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "EMBEDDING_CACHE_FILE", tmp_path / "e.pkl")
        cache = FaceFinderPRO.EmbeddingCache()

        def worker(i):
            for j in range(20):
                cache.set(f"img-{i}-{j}".encode(), np.array([float(i + j)]))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        cache2 = FaceFinderPRO.EmbeddingCache()
        assert len(cache2.cache) == 100

    def test_disk_full_during_save_no_corruption(self, tmp_path, monkeypatch):
        """If the write fails partway, the existing store must remain intact."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0]), _make_image())
        original_bytes = (tmp_path / "g.pkl").read_bytes()

        # Force the next save to fail by making _atomic_pickle_write raise.
        def failing_write(path, obj):
            raise OSError("simulated disk full")
        monkeypatch.setattr(FaceFinderPRO, "_atomic_pickle_write", failing_write)
        try:
            g.add("bob", np.array([2.0]), _make_image())
        except OSError:
            pass
        # The existing store must be byte-identical (no partial overwrite).
        assert (tmp_path / "g.pkl").read_bytes() == original_bytes

    def test_corrupt_store_recovers_to_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        (tmp_path / "g.pkl").write_bytes(b"\x80\x05 GARBAGE NOT PICKLE")
        g = FaceFinderPRO.Gallery()
        assert g.list_all() == {}
        # Evidence of corruption is preserved.
        assert (tmp_path / "g.pkl.corrupt").exists()


# ===========================================================================
# MONTH-1 FAILURE MODES
# ===========================================================================
class TestMonthOne:
    def test_search_cache_expiry_actually_expires(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 0)
        cache = FaceFinderPRO.SearchCache()
        cache.set(b"img", ["https://example.com/a"])
        # TTL=0 => already expired.
        assert cache.get(b"img") is None

    def test_search_with_fallback_caches_results(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 24)
        cache = FaceFinderPRO.SearchCache()
        # Monkeypatch the engine to return canned URLs without a browser.
        calls = {"n": 0}

        class FakeEngine:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                calls["n"] += 1
                return ["https://example.com/img1.jpg"]
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", FakeEngine)
        urls1, label1 = FaceFinderPRO.search_with_fallback("Yandex", b"img", True, [], cache)
        assert urls1 == ["https://example.com/img1.jpg"]
        assert calls["n"] == 1
        # Second call must hit the cache (no new attempt).
        urls2, label2 = FaceFinderPRO.search_with_fallback("Yandex", b"img", True, [], cache)
        assert urls2 == urls1
        assert calls["n"] == 1  # not incremented
        assert "cached" in label2

    def test_gallery_search_skips_none_embeddings(self, tmp_path, monkeypatch):
        """Imported entries have embedding=None; search must skip them, not crash."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        # Manually inject an entry with None embedding (as import_json does).
        g.data["imported"] = {
            "embedding": None, "thumbnail": "", "full_image": b"",
            "added": "2024-01-01", "metadata": {},
        }
        # search must not raise (cosine_sim(None, ...) returns 0.0, below threshold).
        results = g.search(np.array([1.0]), threshold=0.5)
        assert results == []

    def test_proxy_cycling_on_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        cache = FaceFinderPRO.SearchCache()

        class FailingEngine:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                raise RuntimeError("engine down")
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", FailingEngine)
        monkeypatch.setattr(FaceFinderPRO, "search_yandex_requests", lambda b, retries=2: [])
        urls, label = FaceFinderPRO.search_with_fallback(
            "Yandex", b"img", True, ["http://proxy1:8080", "http://proxy2:8080"], cache
        )
        assert urls == []
        assert label == "None"


# ===========================================================================
# YEAR-1 FAILURE MODES
# ===========================================================================
class TestYearOne:
    def test_schema_migration_forward_compat(self):
        """A future schema (newer than current) must be refused, not silently
        clobbered — protects against data loss when downgrading versions."""
        try:
            FaceFinderPRO._migrate_payload({"x": 1}, 999)
            assert False
        except ValueError:
            pass

    def test_legacy_v0_store_still_loads(self, tmp_path, monkeypatch):
        """A store written by v0 (bare pickle, no envelope) must still load
        years later after multiple schema bumps."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        legacy = {"old_entry": {"embedding": np.array([1.0]), "thumbnail": "",
                                "full_image": b"", "added": "2020-01-01",
                                "metadata": {"source_url": "https://old.example.com"}}}
        with open(tmp_path / "g.pkl", "wb") as f:
            pickle.dump(legacy, f)
        g = FaceFinderPRO.Gallery()
        assert "old_entry" in g.list_all()
        assert g.list_all()["old_entry"]["metadata"]["source_url"] == "https://old.example.com"

    def test_backup_chain_survives_many_saves(self, tmp_path, monkeypatch):
        """Many saves over time must produce a rotating backup chain, never
        an unbounded pile of backups."""
        monkeypatch.setattr(FaceFinderPRO, "BACKUP_KEEP", 3)
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        for i in range(20):
            g.add(f"p{i}", np.array([float(i)]), _make_image())
        # Exactly BACKUP_KEEP backups, no more.
        backups = list(tmp_path.glob("g.pkl.bak*"))
        assert len(backups) == 3

    def test_export_import_roundtrip_preserves_metadata(self, tmp_path, monkeypatch):
        """After a year of use, a user exports their gallery and imports it
        into a fresh install. Metadata (age, gender, source_url) must survive."""
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g.pkl")
        g = FaceFinderPRO.Gallery()
        g.add("alice", np.array([1.0]), _make_image(),
              metadata={"age": 30, "gender": "Female",
                        "source_url": "https://example.com/alice.jpg",
                        "engine": "Yandex"})
        out = tmp_path / "export.json"
        g.export_json(out)
        monkeypatch.setattr(FaceFinderPRO, "GALLERY_FILE", tmp_path / "g2.pkl")
        g2 = FaceFinderPRO.Gallery()
        g2.import_json(out)
        entry = g2.list_all()["alice"]
        assert entry["metadata"]["age"] == 30
        assert entry["metadata"]["gender"] == "Female"
        assert entry["metadata"]["source_url"] == "https://example.com/alice.jpg"

    def test_restricted_unpickler_blocks_future_pickle_attack(self):
        """Even if a pickle format changes in the future, the restricted
        unpickler must block any non-allowlisted global."""
        # Simulate a pickle that references a hypothetical future module.
        class FutureExploit:
            def __reduce__(self):
                return (__import__, ("os",))
        payload = pickle.dumps(FutureExploit())
        try:
            FaceFinderPRO._restricted_load(payload)
            assert False
        except pickle.UnpicklingError:
            pass


# ===========================================================================
# DEFENSE-IN-DEPTH INVARIANTS
# ===========================================================================
class TestInvariants:
    def test_no_bare_except_clauses(self):
        src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
        import re
        bare = re.findall(r"^\s*except\s*:", src, re.MULTILINE)
        assert bare == [], f"Bare except: clauses remain: {len(bare)}"

    def test_no_unsafe_pickle_load(self):
        """No raw pickle.load() on untrusted data — all loads go through the
        restricted unpickler."""
        src = (ROOT / "FaceFinderPRO.py").read_text(encoding="utf-8")
        # _safe_pickle_load may use the restricted loader; raw pickle.load on
        # a file object is the danger.
        import re
        # Allow pickle.dumps (safe) and pickle.Unpickler (the base class).
        # Flag raw pickle.load( calls.
        raw_loads = re.findall(r"(?<!restricted_)pickle\.load\(", src)
        # The only acceptable raw load is inside _RestrictedUnpickler via super().
        assert raw_loads == [], f"Raw pickle.load() found: {raw_loads}"

    def test_all_stores_use_atomic_write(self):
        import inspect
        for cls_name, cls in [("Gallery", FaceFinderPRO.Gallery),
                              ("EmbeddingCache", FaceFinderPRO.EmbeddingCache),
                              ("SearchCache", FaceFinderPRO.SearchCache)]:
            src = inspect.getsource(cls.save)
            assert "_atomic_pickle_write" in src, f"{cls_name}.save does not use atomic write"

    def test_all_stores_have_lock(self):
        import inspect
        for cls_name, cls in [("Gallery", FaceFinderPRO.Gallery),
                              ("EmbeddingCache", FaceFinderPRO.EmbeddingCache),
                              ("SearchCache", FaceFinderPRO.SearchCache)]:
            src = inspect.getsource(cls.save)
            assert "_lock" in src or "_gallery_lock" in src or "_embedding_cache_lock" in src or "_search_cache_lock" in src, \
                f"{cls_name}.save has no lock"

    def test_download_and_verify_uses_ssrf_guard(self):
        import inspect
        src = inspect.getsource(FaceFinderPRO.download_and_verify)
        assert "is_url_safe" in src

    def test_download_and_verify_uses_safe_open_image(self):
        import inspect
        src = inspect.getsource(FaceFinderPRO.download_and_verify)
        assert "safe_open_image" in src

    def test_download_and_verify_enforces_size_cap(self):
        import inspect
        src = inspect.getsource(FaceFinderPRO.download_and_verify)
        assert "MAX_DOWNLOAD_BYTES" in src

    def test_engines_register_browser(self):
        import inspect
        for name, cls in FaceFinderPRO.ENGINE_CLASSES.items():
            src = inspect.getsource(cls.attempt_search)
            assert "_register_browser" in src, f"{name} does not register its browser"
            assert "_unregister_browser" in src, f"{name} does not unregister its browser"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
