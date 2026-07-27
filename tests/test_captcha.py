"""Tests for the tiered CAPTCHA persistence layer: detection accuracy, the
auto->manual ladder ordering, gating rules, and the no-hard-failure guarantee.
All offline -- no browser, no network."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import FaceFinderPRO  # noqa: E402

solve = FaceFinderPRO.solve_captcha_with_persistence
detect = FaceFinderPRO.detect_captcha


class _FakeProvider:
    def __init__(self, configured=True, name="fake"):
        self._configured = configured
        self.name = name
    def is_configured(self):
        return self._configured
    def solve(self, challenge):
        return "tok" if self._configured else None


def _cfg(enabled=True, provider=None, allow_manual=False):
    return {
        "enabled": enabled,
        "max_attempts": 3,
        "soft_wait": 8,
        "provider": provider if provider is not None else _FakeProvider(configured=False),
        "allow_manual": allow_manual,
        "manual_timeout": 180,
    }


# ------------------------- detection -------------------------
class TestDetection:
    def test_detect_recaptcha_with_sitekey(self):
        html = '<div class="g-recaptcha" data-sitekey="6LcAbc_-123"></div>'
        ch = detect("https://www.google.com/sorry/index", "", html)
        assert ch is not None
        assert ch.kind == "recaptcha"
        assert ch.sitekey == "6LcAbc_-123"
        assert ch.provider == "Google"

    def test_detect_hcaptcha(self):
        html = '<script src="https://hcaptcha.com/1/api.js"></script><div class="h-captcha"></div>'
        ch = detect("https://example.com/verify", "", html)
        assert ch is not None and ch.kind == "hcaptcha"

    def test_detect_turnstile_interstitial(self):
        html = '<div class="cf-turnstile"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
        ch = detect("https://tineye.com/search", "Just a moment...", html)
        assert ch is not None
        assert ch.kind == "turnstile"
        assert ch.is_interstitial is True

    def test_detect_yandex_showcaptcha(self):
        ch = detect("https://yandex.com/showcaptcha?retpath=x", "", "<html>are you a robot</html>")
        assert ch is not None
        assert ch.provider == "Yandex"
        assert ch.is_interstitial is True

    def test_detect_google_unusual_traffic(self):
        ch = detect("https://www.google.com/sorry/", "", "Our systems have detected unusual traffic")
        assert ch is not None and ch.provider == "Google"

    def test_no_false_positive_on_results_page(self):
        html = ('<html><body><div class="serp">'
                '<img src="https://img.example.com/a.jpg">'
                '<img src="https://img.example.com/b.jpg"></div></body></html>')
        assert detect("https://yandex.com/images/search?rpt=imageview", "Search results", html) is None

    def test_empty_inputs_are_safe(self):
        assert detect("", "", "") is None
        assert detect(None, None, None) is None


# ------------------------- ladder ordering & gating -------------------------
class TestLadder:
    def test_soft_clear_wins_first(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=True,
            soft_clear=lambda: (calls.append("soft"), True)[1],
            auto_solve=lambda ch: (calls.append("auto"), True)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(provider=_FakeProvider(True)),
        )
        assert out.solved and out.tier == "soft"
        assert calls == ["soft"]  # auto/manual never reached

    def test_auto_solve_when_soft_fails(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Google", "recaptcha"),
            engine_name="Google", headless=True,
            soft_clear=lambda: (calls.append("soft"), False)[1],
            auto_solve=lambda ch: (calls.append("auto"), True)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(provider=_FakeProvider(True)),
        )
        assert out.solved and out.tier == "auto"
        assert calls == ["soft", "auto"]

    def test_auto_skipped_when_provider_not_configured(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Google", "recaptcha"),
            engine_name="Google", headless=False,
            soft_clear=lambda: (calls.append("soft"), False)[1],
            auto_solve=lambda ch: (calls.append("auto"), True)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(provider=_FakeProvider(configured=False), allow_manual=True),
        )
        # auto must be skipped (no provider); manual should run since allowed + not headless
        assert "auto" not in calls
        assert out.tier == "manual" and out.solved

    def test_manual_only_when_allowed_and_not_headless(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=False,
            soft_clear=lambda: (calls.append("soft"), False)[1],
            auto_solve=lambda ch: (calls.append("auto"), False)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(provider=_FakeProvider(True), allow_manual=True),
        )
        assert out.solved and out.tier == "manual"
        assert calls == ["soft", "auto", "manual"]  # strict ladder order

    def test_manual_skipped_when_headless(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=True,
            soft_clear=lambda: (calls.append("soft"), False)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(allow_manual=True),
        )
        assert "manual" not in calls  # a human cannot see a headless browser
        assert out.tier == "unsolved" and out.solved is False

    def test_manual_skipped_when_disabled(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=False,
            soft_clear=lambda: (calls.append("soft"), False)[1],
            manual_solve=lambda ch: (calls.append("manual"), True)[1],
            config=_cfg(allow_manual=False),
        )
        assert "manual" not in calls
        assert out.tier == "unsolved" and out.solved is False

    def test_disabled_persistence_returns_immediately(self):
        calls = []
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=False,
            soft_clear=lambda: (calls.append("soft"), True)[1],
            config=_cfg(enabled=False),
        )
        assert out.tier == "disabled" and out.solved is False
        assert calls == []


# ------------------------- no hard failures -------------------------
class TestNoHardFailures:
    def test_never_raises_when_every_tier_throws(self):
        def boom(*a, **k):
            raise RuntimeError("tier blew up")
        before = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_solver_error", 0)
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Google", "recaptcha"),
            engine_name="Google", headless=False,
            soft_clear=boom, auto_solve=boom, manual_solve=boom,
            config=_cfg(provider=_FakeProvider(True), allow_manual=True),
        )
        after = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_solver_error", 0)
        assert out.solved is False and out.tier == "unsolved"
        assert after - before >= 3  # each of the 3 tiers logged an error, none propagated

    def test_all_tiers_fail_degrades_gracefully(self):
        before = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_unsolved", 0)
        out = solve(
            FaceFinderPRO.CaptchaChallenge("Bing", "unknown"),
            engine_name="Bing", headless=False,
            soft_clear=lambda: False,
            auto_solve=lambda ch: False,
            manual_solve=lambda ch: False,
            config=_cfg(provider=_FakeProvider(True), allow_manual=True),
        )
        after = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_unsolved", 0)
        assert out.solved is False and out.tier == "unsolved"
        assert after - before == 1

    def test_detected_metric_increments(self):
        before = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_detected", 0)
        solve(
            FaceFinderPRO.CaptchaChallenge("Yandex", "interstitial"),
            engine_name="Yandex", headless=True,
            soft_clear=lambda: True, config=_cfg(),
        )
        after = FaceFinderPRO.metrics.snapshot()["counters"].get("captcha_detected", 0)
        assert after - before == 1


# ------------------------- provider registry -------------------------
class TestProvider:
    def test_null_provider_is_default(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_PROVIDER", "")
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_URL", "")
        p = FaceFinderPRO.get_captcha_solver_provider()
        assert p.is_configured() is False
        assert p.solve(FaceFinderPRO.CaptchaChallenge("x", "recaptcha")) is None

    def test_http_provider_built_when_configured(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_PROVIDER", "2captcha")
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_URL", "https://solver.example/api")
        p = FaceFinderPRO.get_captcha_solver_provider()
        assert p.is_configured() is True and p.name == "http"

    def test_http_provider_unconfigured_solve_is_none(self):
        p = FaceFinderPRO.HttpCaptchaSolverProvider("", "", 10)
        assert p.is_configured() is False
        assert p.solve(FaceFinderPRO.CaptchaChallenge("x", "recaptcha")) is None


# ------------------------- config validation -------------------------
class TestConfigValidation:
    def test_flags_manual_enabled(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_ALLOW_MANUAL", True)
        warns = FaceFinderPRO.validate_config()
        assert any("Manual CAPTCHA solving is ENABLED" in w for w in warns)

    def test_flags_provider_without_url(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_PROVIDER", "2captcha")
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_SOLVER_URL", "")
        warns = FaceFinderPRO.validate_config()
        assert any("auto-solve tier will be skipped" in w for w in warns)

    def test_flags_negative_soft_wait(self, monkeypatch):
        monkeypatch.setattr(FaceFinderPRO, "CAPTCHA_MAX_ATTEMPTS", 0)
        warns = FaceFinderPRO.validate_config()
        assert any("FACEHUNTER_CAPTCHA_MAX_ATTEMPTS" in w for w in warns)
