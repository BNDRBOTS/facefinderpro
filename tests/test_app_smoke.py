"""Streamlit AppTest smoke test for FaceHunter PRO.

Renders the full application in a headless Streamlit test harness (no browser,
no network, no InsightFace model) to verify the UI mounts cleanly, both tabs
exist, sidebar controls render, and no unhandled exception propagates.

Run with:  FACEHUNTER_SKIP_INSTALL=1 .venv/bin/python -m pytest tests/test_app_smoke.py -q
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("FACEHUNTER_SKIP_INSTALL", "1")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))



def test_app_renders_without_exception(tmp_path, monkeypatch):
    # Isolate persistence into a temp data dir.
    monkeypatch.setenv("FACEHUNTER_DATA_DIR", str(tmp_path / "face_data"))
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "FaceFinderPRO.py"), default_timeout=15)
    at.run()

    assert not at.exception, f"App raised an exception: {at.exception}"
    # Title and tabs.
    assert any("FaceHunter PRO" in str(getattr(h, "value", h)) for h in at.title)
    tab_names = [t.label for t in at.tabs]
    assert "🔎 Search" in tab_names
    assert "📁 Gallery" in tab_names
    # Sidebar engine selector present.
    assert any("Search Engine" in str(getattr(w, "label", w)) for w in at.sidebar.selectbox)
    # File uploader present.
    assert any("Drop your face photo here" in str(getattr(w, "label", "")) for w in at.file_uploader)
    # Hidden report mechanism present (subtle button).
    assert any("Report an issue" in str(getattr(w, "label", "")) for w in at.button)


def test_app_gallery_empty_state(tmp_path, monkeypatch):
    monkeypatch.setenv("FACEHUNTER_DATA_DIR", str(tmp_path / "face_data"))
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(ROOT / "FaceFinderPRO.py"), default_timeout=15)
    at.run()
    assert not at.exception
    # Gallery tab should show the empty-state info message.
    assert any("Gallery is empty" in str(getattr(m, "value", m)) for m in at.info)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
