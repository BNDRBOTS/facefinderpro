"""Audit pass 3 regression tests (BNDR forensic audit, 2026-07-25).

Covers each defect fixed this pass:
  * Redirect SSRF bypass (per-hop validation in _ssrf_safe_request).
  * IPv4-mapped IPv6 SSRF evasion in _is_blocked_ip.
  * SearchCache.get() disk write on a plain miss.
  * Regenerable caches no longer rotate backups (I/O amplification).
  * upgrade_image_url() discarding the size-upgrade on HEAD failure.
  * validate_config() startup sanity warnings.
  * _safe_log_tail() URL path/query redaction (privacy).
  * clear_results() resetting a stale pending_delete.

Run with: FACEHUNTER_SKIP_INSTALL=1 python3 /data/runtests.py /data/ffpro
"""
import io, os, sys, types, importlib.util
from pathlib import Path
import numpy as np
from PIL import Image

os.environ.setdefault("FACEHUNTER_SKIP_INSTALL", "1")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location("FaceFinderPRO", ROOT / "FaceFinderPRO.py")
FaceFinderPRO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FaceFinderPRO)

class _FakeResp:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False

class _FakeRequests:
    def __init__(self, script):
        self.script = list(script); self.calls = []
    def request(self, method, url, **kw):
        self.calls.append(url); return self.script.pop(0)

SAFE  = "http://93.184.216.34/a.jpg"
SAFE2 = "http://93.184.216.34/final.jpg"
INTERNAL = "http://169.254.169.254/latest/meta-data/"

class TestSSRFRedirect:
    def test_follows_safe_redirect(self, monkeypatch):
        fake = _FakeRequests([_FakeResp(302, {"Location": SAFE2}), _FakeResp(200, {})])
        monkeypatch.setattr(FaceFinderPRO, "requests", fake)
        resp = FaceFinderPRO._ssrf_safe_request("GET", SAFE, timeout=5, headers={})
        assert resp is not None and resp.status_code == 200
        assert fake.calls == [SAFE, SAFE2]

    def test_blocks_redirect_to_internal(self, monkeypatch):
        fake = _FakeRequests([_FakeResp(302, {"Location": INTERNAL})])
        monkeypatch.setattr(FaceFinderPRO, "requests", fake)
        resp = FaceFinderPRO._ssrf_safe_request("GET", SAFE, timeout=5, headers={})
        assert resp is None; assert fake.calls == [SAFE]

    def test_blocks_redirect_loop(self, monkeypatch):
        fake = _FakeRequests([_FakeResp(302, {"Location": SAFE}) for _ in range(20)])
        monkeypatch.setattr(FaceFinderPRO, "requests", fake)
        resp = FaceFinderPRO._ssrf_safe_request("GET", SAFE, timeout=5, headers={}, max_redirects=5)
        assert resp is None; assert len(fake.calls) <= 6

    def test_request_exception_returns_none(self, monkeypatch):
        class Boom:
            def request(self, *a, **k): raise RuntimeError("network down")
        monkeypatch.setattr(FaceFinderPRO, "requests", Boom())
        assert FaceFinderPRO._ssrf_safe_request("GET", SAFE, timeout=5, headers={}) is None

class TestMappedIPv6:
    def test_blocks_ipv4_mapped_metadata(self):
        assert FaceFinderPRO._is_blocked_ip("::ffff:169.254.169.254") is True
        assert FaceFinderPRO._is_blocked_ip("::ffff:127.0.0.1") is True
    def test_allows_mapped_public(self):
        assert FaceFinderPRO._is_blocked_ip("::ffff:93.184.216.34") is False

class TestSearchCacheNoWriteOnMiss:
    def test_plain_miss_does_not_write(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        cache = FaceFinderPRO.SearchCache()
        assert cache.get(b"never-seen") is None
        assert not (tmp_path / "s.pkl").exists()

    def test_expiry_evicts_and_saves(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 0)
        cache = FaceFinderPRO.SearchCache()
        cache.set(b"img", ["https://example.com/a"])
        assert cache.get(b"img") is None
        assert b"img" not in list(cache.cache)

class TestCacheNoBackup:
    def test_embedding_cache_no_bak(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "EMBEDDING_CACHE_FILE", tmp_path / "e.pkl")
        cache = FaceFinderPRO.EmbeddingCache()
        cache.set(b"k1", np.array([1.0]))
        cache.set(b"k2", np.array([2.0]))
        assert not (tmp_path / "e.pkl.bak1").exists()

    def test_search_cache_no_bak(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        cache = FaceFinderPRO.SearchCache()
        cache.set(b"k1", ["https://example.com/1"])
        cache.set(b"k2", ["https://example.com/2"])
        assert not (tmp_path / "s.pkl.bak1").exists()

class TestUpgradeUrlOnFailure:
    def test_head_failure_keeps_size_upgrade(self, monkeypatch):
        class Boom:
            def Session(self): raise RuntimeError("no network")
        monkeypatch.setattr(FaceFinderPRO, "requests", Boom())
        out = FaceFinderPRO.upgrade_image_url("https://img.example.com/p.jpg?w=100&h=100")
        assert out is not None and out.startswith("http")
        assert "w=800" in out and "h=800" in out

class TestValidateConfig:
    def test_warns_download_exceeds_total(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "MAX_DOWNLOAD_BYTES", 10**9)
        monkeypatch.setattr(FaceFinderPRO, "MAX_SEARCH_TOTAL_BYTES", 10**6)
        warns = FaceFinderPRO.validate_config()
        assert any("per-search budget" in w for w in warns)

    def test_warns_ssrf_disabled(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SSRF_BLOCK_PRIVATE", False)
        warns = FaceFinderPRO.validate_config()
        assert any("SSRF protection is DISABLED" in w for w in warns)

    def test_clean_config_no_warnings(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SSRF_BLOCK_PRIVATE", True)
        monkeypatch.setattr(FaceFinderPRO, "MAX_DOWNLOAD_BYTES", 25*1024*1024)
        monkeypatch.setattr(FaceFinderPRO, "MAX_SEARCH_TOTAL_BYTES", 250*1024*1024)
        assert FaceFinderPRO.validate_config() == []

class TestLogTailPrivacy:
    def test_redacts_url_path_and_query(self, tmp_path, monkeypatch):
        log = tmp_path / "err.log"
        log.write_text("failed fetching https://images.example.com/people/jane_doe.jpg?token=SEEKRIT here")
        monkeypatch.setattr(FaceFinderPRO, "ERROR_LOG_FILE", log)
        tail = FaceFinderPRO._safe_log_tail()
        assert "jane_doe" not in tail
        assert "SEEKRIT" not in tail
        assert "https://images.example.com/[redacted]" in tail

class TestClearResultsPendingDelete:
    def test_resets_pending_delete(self, monkeypatch):
        fake_st = types.ModuleType("streamlit")
        class SS(dict):
            def __getattr__(self, k): return self.get(k)
            def __setattr__(self, k, v): self[k] = v
        fake_st.session_state = SS()
        fake_st.session_state["pending_delete"] = "stale-name"
        sys.modules["streamlit"] = fake_st
        try:
            FaceFinderPRO.clear_results()
            assert fake_st.session_state.get("pending_delete") is None
            assert fake_st.session_state.get("matches") == []
        finally:
            sys.modules.pop("streamlit", None)
