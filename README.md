# FaceHunter PRO™

Production-grade **reverse face-image search** with a local gallery, multi-engine
stealth browser automation, embedding caching, and verified candidate matching.

This is the **remediated artifact** produced by a line-by-line forensic audit of
the supplied `FaceFinderPRO.py`. Every verified defect has been corrected; the
application's verified intent, data, schemas, and user-visible behavior are
preserved. See [Audit & Remediation](#audit--remediation) for the full record.

---

## Features

- **Multi-engine reverse image search** — Yandex, Google, Bing, and TinEye,
  each driven by a stealth Playwright browser (randomized user agent, viewport,
  locale, timezone, Bezier mouse motion, human-like typing/scrolling/clicking).
- **Engine fallback chain** — primary engine → Yandex → requests-based fallback,
  with retry + proxy cycling.
- **Local face gallery** — store embeddings, thumbnails, full images, and
  metadata (source URL, engine, age, gender, query thumbnail). Atomic, thread-safe
  pickle persistence with corruption recovery.
- **Embedding cache** — SHA-256 keyed, avoids recomputing embeddings for
  duplicate image bytes.
- **Search cache** — 24 h TTL, SHA-256 keyed candidate-URL cache.
- **Face attribute filters** — filter the query image's faces by age/gender.
- **Verified matching** — candidates are downloaded, re-embedded, and scored by
  cosine similarity; only matches above threshold are shown.
- **Pagination, sorting, similarity filter, auto-save**.
- **Hidden one-click diagnostic report** (BNDR.Labs) for unrecoverable failures —
  the user only ever sees a friendly acknowledgement; no internal material leaks.

---

## Quick start

```bash
# 1. (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
python -m playwright install chromium

# 3. (Optional) configure environment
cp .env.example .env               # edit as needed

# 4. Run
streamlit run FaceFinderPRO.py
```

On first launch the app auto-installs any missing packages and the Chromium
browser, then exits with a prompt to restart. Set `FACEHUNTER_SKIP_INSTALL=1`
to disable auto-install (e.g. in CI).

> **InsightFace model:** the `buffalo_l` model is downloaded automatically to
> `~/.insightface/models/` on first use. An internet connection is required for
> this one-time download and for live web searches.

---

## Configuration

All configuration is via environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|---|---|---|
| `FACEHUNTER_DATA_DIR` | `face_data` | Persistence directory |
| `FACEHUNTER_MAX_UPLOAD_BYTES` | `20000000` | Max upload size |
| `FACEHUNTER_MAX_IMAGE_DIMENSION` | `1024` | Downscale longest side |
| `FACEHUNTER_SEARCH_CACHE_TTL_HOURS` | `24` | Search cache TTL |
| `FACEHUNTER_ERROR_LOG_MAX_BYTES` | `5000000` | Error log rotation size |
| `FACEHUNTER_MAX_IMAGE_PIXELS` | `50000000` | Decompression-bomb pixel cap |
| `FACEHUNTER_MAX_DOWNLOAD_BYTES` | `25000000` | Per-candidate download cap |
| `FACEHUNTER_MAX_SEARCH_TOTAL_BYTES` | `250000000` | Per-search total-bytes budget |
| `FACEHUNTER_GALLERY_MAX_ENTRIES` | `5000` | Gallery cap (archives overflow) |
| `FACEHUNTER_EMBEDDING_CACHE_MAX_ENTRIES` | `20000` | Embedding cache LRU cap |
| `FACEHUNTER_SEARCH_CACHE_MAX_ENTRIES` | `5000` | Search cache LRU cap |
| `FACEHUNTER_BACKUP_KEEP` | `5` | Rotating backups per store |
| `FACEHUNTER_PICKLE_HMAC_SECRET` | _(unset)_ | Optional HMAC for pickle integrity |
| `FACEHUNTER_SSRF_BLOCK_PRIVATE` | `1` | Block private/loopback IPs in downloads |
| `BNDR_LABS_REPORT_URL` | _(unset)_ | Hidden diagnostic endpoint |
| `BNDR_LABS_REPORT_TIMEOUT` | `10` | Report POST timeout |
| `FACEHUNTER_SKIP_INSTALL` | _(unset)_ | Skip auto-installer |

---

## Usage

1. Open the app in your browser (Streamlit prints the URL, default
   `http://localhost:8501`).
2. **Search tab** — drop a face photo, adjust the similarity threshold, max
   results, engine, headless mode, proxies, and age/gender filters in the
   sidebar, then click **🚀 Run Search**.
3. Verified matches appear with similarity, source URL, and an **Add to
   Gallery** form. Use **Prev / Next** to paginate.
4. **Gallery tab** — add new faces manually, view thumbnails and metadata, and
   delete entries (with a two-step confirmation).
5. **Report an issue** — a subtle button in the sidebar's *Help* expander sends
   a sanitized diagnostic report. You will only see:
   > Message sent. Thank you for notifying us. We'll address it as soon as possible.

---

## Data & persistence

All data lives under `FACEHUNTER_DATA_DIR` (default `./face_data/`):

```
face_data/
├── gallery.pkl            # local gallery (embeddings, thumbnails, metadata)
├── embedding_cache.pkl    # SHA-256 -> embedding cache
├── search_cache.pkl       # SHA-256 -> (timestamp, [urls]) TTL cache
├── errors.log             # rotated error log
└── reports/               # sanitized local BNDR.Labs diagnostic reports
```

- Writes are **atomic** (temp file + `os.replace` + `fsync`) with restrictive
  `0600` permissions, so an interrupt or crash cannot corrupt the store.
- Corrupt pickles are detected at load, backed up as `*.corrupt` (evidence
  preserved), and reset to a safe default so the app keeps running.
- All shared stores are guarded by thread locks; concurrent candidate
  verification (10 workers) is safe.

---

## Testing

```bash
pip install -r requirements.txt   # includes pytest + ruff
FACEHUNTER_SKIP_INSTALL=1 python -m pytest tests/ -q
ruff check .                       # lint
python -m py_compile FaceFinderPRO.py
```

The suite covers every repaired defect, every hardening control, and the
critical UI render path — **113 tests** across three files:

- `tests/test_facefinder.py` — 30 regression tests (the original 20 audit
  findings: persistence, concurrency, validation, URL upgrade, BNDR report
  sanitization, no bare `except:`, etc.).
- `tests/test_hardening.py` — 81 production-hardening tests organized by
  domain: SSRF, decompression bombs, path traversal, restricted-unpickler RCE
  defense, HMAC tamper detection, schema migration, backup/restore,
  export/import, LRU cache eviction, gallery cap + archival, metrics, browser
  lifecycle, graceful shutdown, metadata sanitization, and explicit
  **week-1 / month-1 / year-1** failure-mode scenarios.
- `tests/test_app_smoke.py` — 2 Streamlit `AppTest` smoke tests (full UI
  renders without exception, tabs/controls/empty-state present).

---

## Production Hardening

The second-pass hardening closes every week/month/year failure mode identified
during the audit. Highlights (all env-configurable, see `.env.example`):

- **SSRF defense** — candidate URLs are resolved and any private/loopback/
  link-local/reserved IP (incl. cloud metadata `169.254.169.254`) is refused
  before any fetch. Disable with `FACEHUNTER_SSRF_BLOCK_PRIVATE=0`.
- **Decompression-bomb defense** — `safe_open_image()` enforces
  `MAX_IMAGE_PIXELS` and treats PIL's `DecompressionBombWarning` as an error.
- **Restricted unpickler + HMAC** — all gallery/cache loads go through a
  `RestrictedUnpickler` that only allows builtins/numpy/datetime globals (RCE
  defense). Optionally sign stores with `FACEHUNTER_PICKLE_HMAC_SECRET` for
  tamper detection.
- **Schema versioning + migration** — stores carry a schema stamp; legacy v0
  bare-pickle stores auto-migrate; future schemas are refused (not clobbered).
- **Rotating backups** — every save shifts `.bak{N-1}→.bak{N}` and writes
  `.bak1`, keeping `BACKUP_KEEP` copies. One-click restore in the sidebar.
- **Export / Import** — gallery metadata exports to JSON (embeddings/images
  never leave the machine); import reconstructs entries for re-embedding.
- **LRU caps** — gallery (5000), embedding cache (20000), search cache (5000)
  evict oldest entries; gallery overflow is **archived**, never silently dropped.
- **Per-search byte budget** — `MAX_SEARCH_TOTAL_BYTES` (250 MB) caps total
  candidate bytes fetched per search; streaming GET aborts oversized responses.
- **Browser lifecycle guard** — every Playwright browser is registered and
  guaranteed closed on exit (atexit + finally), preventing zombie Chromium.
- **Graceful shutdown** — atexit hook flushes dirty caches to disk.
- **Metrics** — in-process counters (downloads, cache hits/misses, SSRF
  blocks, etc.) exposed in the sidebar "Diagnostics & Data" expander.
- **Filename / metadata sanitization** — gallery names are stripped of path
  separators, control chars, and capped; metadata values are coerced to safe
  primitives with length caps (XSS defense in depth).
- **Streaming downloads** — `requests.get(stream=True)` aborts the moment a
  response exceeds `MAX_DOWNLOAD_BYTES`, preventing memory exhaustion.

---

## Deployment

- **Local / single user:** `streamlit run FaceFinderPRO.py` (default).
- **Container:** base on `python:3.12-slim`, `pip install -r requirements.txt`,
  `python -m playwright install chromium --with-deps`, then launch with
  `streamlit run FaceFinderPRO.py --server.port 8080 --server.address 0.0.0.0`.
  Mount `FACEHUNTER_DATA_DIR` as a persistent volume. Set
  `FACEHUNTER_PICKLE_HMAC_SECRET` to a random 32-byte hex for tamper detection.
- **Reverse proxy:** put Streamlit behind nginx/Caddy with WebSocket support
  (Streamlit requires `/_stcore/stream`).
- **Health check:** Streamlit exposes `/_stcore/health` returning `ok`.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| `ModuleNotFoundError` on first run | Let the auto-installer run, or `pip install -r requirements.txt` manually. |
| InsightFace model download fails | Ensure outbound HTTPS to `*.s3.amazonaws.com` is allowed; the model caches under `~/.insightface/models/`. |
| Playwright `Executable doesn't exist` | Run `python -m playwright install chromium`. |
| All searches return "No candidate images found" | The engines' DOM may have changed; check `face_data/errors.log`. Headless mode is less stealthy — try with it off. |
| `Gallery is empty` persists after adding | Confirm `FACEHUNTER_DATA_DIR` is writable. |
| Slow first search | The first search loads the InsightFace model (~300 MB) into memory; subsequent searches reuse it. |
| Candidate downloads all blocked | Check `FACEHUNTER_SSRF_BLOCK_PRIVATE`; if your network resolves public hosts to private IPs (VPN), you may need to relax it. |
| Corrupt store on startup | The app auto-recovers to an empty default and preserves evidence as `*.corrupt`; use "Restore gallery from backup" in the sidebar. |
| HMAC verification fails | A store was written with a different `FACEHUNTER_PICKLE_HMAC_SECRET`; unset it or restore the correct secret, then restore from backup. |

---

## Audit & Remediation

The supplied `FaceFinderPRO.py` was audited line-by-line from zero assumptions.
**Verified findings and their root causes** (full detail in the completion
record `COMPLETION_RECORD.md`):

1. **Markdown code fence** — the file began with ` ```python ` and ended with
   ` ``` `, so `python FaceFinderPRO.py` raised `SyntaxError` on line 1.
2. **Duplicate class definitions** — `SearchEngine`, `YandexEngine`,
   `GoogleEngine` were defined twice; the second (refactored) set silently
   shadowed the first, while the refactor's own comment admitted Bing and
   TinEye were "omitted for brevity."
3. **Bing/TinEye `AttributeError`** — selecting Bing or TinEye called
   `attempt_search`, which those classes never implemented (they still had the
   legacy `search()`), crashing every Bing/TinEye search.
4. **Dead placeholder `search_with_fallback`** — a first definition ended with
   `pass  # placeholder`; only the second (re)definition was real.
5. **`page.mouse.position` does not exist** in Playwright's Python API;
   `bezier_move` raised `AttributeError`, silently disabling all human-like
   clicking and forcing every engine into the retry/fallback path.
6. **`requests.head(..., max_redirects=...)`** — `max_redirects` is a
   `Session` attribute, not a per-request kwarg; the `TypeError` was swallowed,
   so `upgrade_image_url` never followed redirects.
7. **`base64.b64encode(io.BytesIO()).getvalue()`** — `b64encode` requires
   bytes; this raised `TypeError` and crashed auto-save before the correct
   thumbnail was generated.
8. **Gallery delete never deleted** — `to_delete` was rebuilt every rerun, so
   the Confirm button click landed in a run where `to_delete` was empty.
9. **Thread-unsafe persistence** — `EmbeddingCache.set` / `SearchCache.set` /
   `Gallery.save` wrote pickles from 10 concurrent workers with no lock,
   corrupting files under load.
10. **Non-atomic writes** — direct `pickle.dump` to the target path; an
    interrupt/crash mid-write left a corrupt store.
11. **Corrupt pickles unrecoverable** — a single bad byte made the app crash on
    load with no fallback.
12. **`seen_urls` TOCTOU race** — check-then-add across threads allowed
    duplicate downloads.
13. **`cosine_sim` divide-by-zero** — zero-norm embeddings produced `nan`.
14. **No upload validation** — oversized/corrupt images reached the model.
15. **`search_yandex_requests` assumed JSON** — non-JSON responses raised.
16. **`st.set_page_config` ordering** — module-level `face_app =
    get_face_app()` ran `@st.cache_resource` before `set_page_config`.
17. **Bare `except:`** clauses swallowed `KeyboardInterrupt`/`SystemExit`.
18. **Unused imports** (`math`, `Union`).
19. **Error log grew unbounded** — no rotation.
20. **No BNDR.Labs report mechanism**, no README, no requirements, no tests.

Each finding was corrected with the smallest non-regressive fix; behavior,
schemas, and data are preserved. See `COMPLETION_RECORD.md` for the per-file
change log, commands executed, and final verification results.


---

## Audit trail

This build was independently audited on 2026-07-25 (Pass 3). Start with
[`AUDIT.md`](AUDIT.md) for findings, fixes, and an **honest verification
matrix** (the logic core is test-proven; the Streamlit UI, InsightFace, and
Playwright layers are static-reviewed only — they cannot execute in a
no-network / no-GPU sandbox). Security posture is in [`SECURITY.md`](SECURITY.md);
biometric-law, ToS, and privacy considerations are in
[`LEGAL_AND_PRIVACY.md`](LEGAL_AND_PRIVACY.md). Deploy reproducibly with the
`Dockerfile` / `Makefile`. Full history in [`CHANGELOG.md`](CHANGELOG.md).

### Test count
- Prior suites: `tests/test_facefinder.py` (28) + `tests/test_hardening.py` (83).
- Added since: `tests/test_audit_pass3.py` (16) + `tests/test_concurrent.py` (12).
- **139 logic tests, all passing** offline; `tests/test_app_smoke.py` (2)
  requires a Streamlit install to run.

## Concurrent multi-engine search

Pick one, several, or all engines in the sidebar (**Search Engines (searched
concurrently)**). Selected engines run **in parallel** under a governor and
their candidate results are merged in selection order and de-duplicated.

The parallelism is bounded and time-boxed — it is engineered not to become a
resource incident:

| Knob | Default | Purpose |
|---|---|---|
| `FACEHUNTER_MAX_CONCURRENT_ENGINES` | 3 | Caps simultaneous browsers; extra engines queue and fill freed slots. Bounds peak RAM/CPU. |
| `FACEHUNTER_CONCURRENT_SEARCH_DEADLINE_SECONDS` | 90 | Global wall-clock budget. Engines still running at the deadline are abandoned; results already gathered are returned (**partial-result resilience**). `0` disables. |
| `FACEHUNTER_ENGINE_NAV_TIMEOUT_SECONDS` | 30 | Per-engine navigation timeout and the ceiling on how long an abandoned engine keeps running before winding down. |

Behavior guarantees:
- **A single hung engine can never stall the whole search** — the deadline caps
  the phase and returns partial intel; the run label notes which engines timed
  out.
- **No zombie Chromium** — abandoned workers wind down via their own nav
  timeout, and the atexit browser guard reclaims any straggler.
- **A single selected engine is byte-for-byte the legacy path** — it delegates
  to the original `search_with_fallback` (shared cache + Yandex/requests
  fallback), so nothing regresses.
- Observability via in-process metrics: `concurrent_search_runs`,
  `engine_attempts`, `engine_success`, `engine_empty`, `engine_timeout`.

## Skip the Playwright Chromium download (use system Chrome)

The `playwright install chromium` step downloads a ~180 MB browser and does not
resume on failure, so a flaky connection can stall it indefinitely. To avoid it
entirely, point FaceHunter at a browser you already have installed:

```bash
export FACEHUNTER_BROWSER_CHANNEL=chrome   # uses system Google Chrome
streamlit run FaceFinderPRO.py
```

Accepts `chrome`, `chrome-beta`, `msedge`, or `chromium`. If the requested
channel is not installed, the app automatically falls back to Playwright's
bundled Chromium (never a hard failure).
