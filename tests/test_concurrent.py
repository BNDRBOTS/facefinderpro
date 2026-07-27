"""Concurrent multi-engine search tests (feature + regression guard).

Proves:
  * search_engines_concurrent runs multiple engines IN PARALLEL (barrier proof).
  * results from several engines are merged and de-duplicated.
  * a single selected engine still delegates to the untouched
    search_with_fallback (no regression: cache + fallback preserved).
  * empty / unknown selections degrade gracefully.
  * merged multi-engine results are cached.
"""
import os, sys, threading, importlib.util
from pathlib import Path

os.environ.setdefault("FACEHUNTER_SKIP_INSTALL", "1")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_spec = importlib.util.spec_from_file_location("FaceFinderPRO", ROOT / "FaceFinderPRO.py")
FaceFinderPRO = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FaceFinderPRO)


def _engine_returning(urls, barrier=None):
    class _E:
        def __init__(self, headless=False):
            pass
        def attempt_search(self, image_bytes, proxy=None):
            if barrier is not None:
                # Only returns if EVERY engine reaches the barrier together;
                # a one-at-a-time (sequential) run would time out here.
                barrier.wait()
            return list(urls)
    return _E


class TestConcurrency:
    def test_engines_run_in_parallel(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        barrier = threading.Barrier(3, timeout=8)
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex",
                            _engine_returning(["https://y.example/1"], barrier))
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google",
                            _engine_returning(["https://g.example/1"], barrier))
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Bing",
                            _engine_returning(["https://b.example/1"], barrier))
        cache = FaceFinderPRO.SearchCache()
        urls, label = FaceFinderPRO.search_engines_concurrent(
            ["Yandex", "Google", "Bing"], b"img", True, [], cache)
        # If they ran sequentially the barrier would time out and urls == [].
        assert set(urls) == {"https://y.example/1", "https://g.example/1", "https://b.example/1"}
        assert "Yandex" in label and "Google" in label and "Bing" in label

    def test_merges_and_dedups(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        shared = "https://dup.example/same.jpg"
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex",
                            _engine_returning([shared, "https://y.example/1"]))
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google",
                            _engine_returning([shared, "https://g.example/1"]))
        cache = FaceFinderPRO.SearchCache()
        urls, label = FaceFinderPRO.search_engines_concurrent(
            ["Yandex", "Google"], b"img", True, [], cache)
        assert urls.count(shared) == 1                      # de-duplicated
        assert set(urls) == {shared, "https://y.example/1", "https://g.example/1"}
        assert urls[0] == shared                            # selection order preserved

    def test_multi_engine_result_is_cached(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        calls = {"y": 0, "g": 0}
        def counting(key, urls):
            class _E:
                def __init__(self, headless=False):
                    pass
                def attempt_search(self, image_bytes, proxy=None):
                    calls[key] += 1
                    return list(urls)
            return _E
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", counting("y", ["https://y/1"]))
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google", counting("g", ["https://g/1"]))
        cache = FaceFinderPRO.SearchCache()
        u1, _ = FaceFinderPRO.search_engines_concurrent(["Yandex", "Google"], b"img", True, [], cache)
        u2, label2 = FaceFinderPRO.search_engines_concurrent(["Yandex", "Google"], b"img", True, [], cache)
        assert set(u1) == set(u2)
        assert calls == {"y": 1, "g": 1}   # second call served from cache
        assert "cached" in label2


class TestNoRegressionSingleEngine:
    def test_single_engine_delegates_to_fallback_and_caches(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_TTL_HOURS", 24)
        calls = {"n": 0}
        class FakeEngine:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                calls["n"] += 1
                return ["https://example.com/img1.jpg"]
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", FakeEngine)
        cache = FaceFinderPRO.SearchCache()
        u1, l1 = FaceFinderPRO.search_engines_concurrent(["Yandex"], b"img", True, [], cache)
        u2, l2 = FaceFinderPRO.search_engines_concurrent(["Yandex"], b"img", True, [], cache)
        assert u1 == ["https://example.com/img1.jpg"]
        assert u2 == u1
        assert calls["n"] == 1          # cache hit on the 2nd call (legacy behavior)
        assert "cached" in l2

    def test_single_engine_falls_back_to_yandex(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        class Failing:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                raise RuntimeError("down")
        # Selecting Google alone must still fall back to Yandex, then requests.
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google", Failing)
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", Failing)
        monkeypatch.setattr(FaceFinderPRO, "search_yandex_requests",
                            lambda b, retries=2: ["https://req.example/1"])
        cache = FaceFinderPRO.SearchCache()
        urls, label = FaceFinderPRO.search_engines_concurrent(["Google"], b"img", True, [], cache)
        assert urls == ["https://req.example/1"]
        assert "requests fallback" in label


class TestDegradesGracefully:
    def test_empty_selection(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        cache = FaceFinderPRO.SearchCache()
        assert FaceFinderPRO.search_engines_concurrent([], b"img", True, [], cache) == ([], "None")

    def test_unknown_engines_only(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        cache = FaceFinderPRO.SearchCache()
        assert FaceFinderPRO.search_engines_concurrent(["Nope", "Bogus"], b"img", True, [], cache) == ([], "None")

    def test_all_engines_fail_uses_requests(self, tmp_path, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        class Failing:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                raise RuntimeError("down")
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", Failing)
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google", Failing)
        monkeypatch.setattr(FaceFinderPRO, "search_yandex_requests",
                            lambda b, retries=2: ["https://req.example/1"])
        cache = FaceFinderPRO.SearchCache()
        urls, label = FaceFinderPRO.search_engines_concurrent(["Yandex", "Google"], b"img", True, [], cache)
        assert urls == ["https://req.example/1"]
        assert "requests fallback" in label


class TestGovernor:
    """The concurrency GOVERNOR: bounded parallelism, a global deadline with
    partial-result resilience, configurable nav timeout, and config validation.
    """

    def test_bounded_parallelism_respects_cap(self, tmp_path, monkeypatch):
        import time
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "MAX_CONCURRENT_ENGINES", 2)
        state = {"cur": 0, "max": 0}
        lock = threading.Lock()

        def factory(urls):
            class E:
                def __init__(self, headless=False):
                    pass
                def attempt_search(self, image_bytes, proxy=None):
                    with lock:
                        state["cur"] += 1
                        state["max"] = max(state["max"], state["cur"])
                    time.sleep(0.25)
                    with lock:
                        state["cur"] -= 1
                    return list(urls)
            return E

        for name, u in [("Yandex", ["https://y/1"]), ("Google", ["https://g/1"]),
                        ("Bing", ["https://b/1"]), ("TinEye", ["https://t/1"])]:
            monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, name, factory(u))
        cache = FaceFinderPRO.SearchCache()
        urls, _ = FaceFinderPRO.search_engines_concurrent(
            ["Yandex", "Google", "Bing", "TinEye"], b"img", True, [], cache)
        # Governor never let more than the cap run at once...
        assert state["max"] <= 2
        # ...but every engine still eventually ran and contributed.
        assert set(urls) == {"https://y/1", "https://g/1", "https://b/1", "https://t/1"}

    def test_deadline_yields_partial_results(self, tmp_path, monkeypatch):
        import time
        monkeypatch.setattr(FaceFinderPRO, "SEARCH_CACHE_FILE", tmp_path / "s.pkl")
        monkeypatch.setattr(FaceFinderPRO, "MAX_CONCURRENT_ENGINES", 3)
        monkeypatch.setattr(FaceFinderPRO, "CONCURRENT_SEARCH_DEADLINE_SECONDS", 1)

        class Fast:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                return ["https://fast/1"]

        class Slow:
            def __init__(self, headless=False):
                pass
            def attempt_search(self, image_bytes, proxy=None):
                time.sleep(3)
                return ["https://slow/1"]

        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Yandex", Fast)
        monkeypatch.setitem(FaceFinderPRO.ENGINE_CLASSES, "Google", Slow)
        before = FaceFinderPRO.metrics.snapshot()["counters"].get("engine_timeout", 0)
        cache = FaceFinderPRO.SearchCache()
        t0 = time.time()
        urls, label = FaceFinderPRO.search_engines_concurrent(
            ["Yandex", "Google"], b"img", True, [], cache)
        elapsed = time.time() - t0
        after = FaceFinderPRO.metrics.snapshot()["counters"].get("engine_timeout", 0)
        assert "https://fast/1" in urls          # partial results returned
        assert "https://slow/1" not in urls      # slow engine abandoned
        assert "timed out" in label and "Google" in label
        assert after - before >= 1               # timeout recorded in metrics
        assert elapsed < 2.5                     # did NOT block on the slow engine

    def test_engine_nav_timeout_is_configurable(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "ENGINE_NAV_TIMEOUT_SECONDS", 42)
        assert FaceFinderPRO.SearchEngine().timeout == 42

    def test_validate_config_flags_deadline_below_nav(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CONCURRENT_SEARCH_DEADLINE_SECONDS", 5)
        monkeypatch.setattr(FaceFinderPRO, "ENGINE_NAV_TIMEOUT_SECONDS", 30)
        warns = FaceFinderPRO.validate_config()
        assert any("CONCURRENT_SEARCH_DEADLINE_SECONDS" in w and "NAV_TIMEOUT" in w for w in warns)
