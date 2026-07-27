# Changelog

## [Audit Pass 3] — 2026-07-25 (BNDR forensic audit)
Full A→Z review. 111 prior tests kept green; 16 new tests added (127 total,
all passing via the offline logic runner). See `AUDIT.md` for the honest
verification matrix (UI / ML / browser layers are static-reviewed only — they
cannot run in a no-network, no-GPU sandbox).

### Fixed
- **SSRF via HTTP redirect**: candidate fetches now validate every redirect hop
  (`_ssrf_safe_request`); `allow_redirects=True` bypass closed (HEAD + GET).
- **SSRF via IPv4-mapped IPv6**: `_is_blocked_ip` now unwraps `::ffff:` mapped
  addresses; removed a duplicate `is_multicast` check.
- **`upgrade_image_url`**: no longer discards the size-upgrade on HEAD/network
  failure (was silently returning low-res originals; fixes the one red test).
- **Byte-budget race**: per-search total-bytes counter now mutated under a lock.
- **`clear_results`**: clears a stale `pending_delete` confirmation.

### Changed (sustainability)
- Regenerable caches (`EmbeddingCache`, `SearchCache`) no longer rotate backups
  on every `set()` (removed O(n)/insert, O(n²)/search disk amplification).
  Gallery backups retained.
- `SearchCache.get()` no longer writes to disk on a plain cache miss.

### Added
- `validate_config()` startup sanity checks, surfaced as sidebar warnings.
- URL path/query redaction in `_safe_log_tail()` (privacy).
- `AUDIT.md`, `SECURITY.md`, `LEGAL_AND_PRIVACY.md`, `Dockerfile`,
  `.dockerignore`, `Makefile`, `.gitignore`, `CHANGELOG.md`,
  `tests/test_audit_pass3.py`.

### Known / deferred (documented, not silently changed)
- Gallery stores the *query* embedding rather than the matched image's own
  embedding — flagged for a product decision (see `AUDIT.md`).
- DNS-rebinding TOCTOU partially open — needs IP-pinning or egress firewall
  (see `SECURITY.md`).
- `pickle` at rest (restricted + HMAC-guarded) — JSON/SQLite recommended.

## [Feature] Concurrent multi-engine search — 2026-07-27

### Added
- **`search_engines_concurrent()`**: searches one *or many* engines. Multiple
  engines run in **parallel** (one worker thread each) and their candidate URLs
  are merged in selection order and de-duplicated. A single selected engine
  delegates to the untouched `search_with_fallback()`, so legacy behavior is
  byte-for-byte preserved.
- **`_attempt_engine_direct()`**: per-engine attempt (retries + proxy cycling,
  no cross-engine fallback) used by the concurrent path.
- **Sidebar**: the single-choice "Search Engine" dropdown is now a
  **"Search Engines (searched concurrently)"** multiselect — pick one, several,
  or all. Empty selection is rejected with a clear message.
- `tests/test_concurrent.py`: 8 tests, including a **barrier-based proof** that
  engines actually run concurrently (a sequential run would deadlock/time out),
  plus merge/dedup, caching, single-engine no-regression, and graceful-degrade
  cases.

### Guarantees
- **No regression**: all 127 prior tests still pass unchanged; single-engine
  path is identical to before. Total suite now **135 passing** offline.

## [Feature] Governed concurrency — 2026-07-27 (v2)

Upgraded the naive multi-engine fan-out into a governed, production-grade
concurrency model.

### Added
- **Concurrency governor** in `search_engines_concurrent()`:
  - `MAX_CONCURRENT_ENGINES` (default 3) bounds simultaneous browsers; extra
    selected engines queue and start as slots free up.
  - `CONCURRENT_SEARCH_DEADLINE_SECONDS` (default 90) global wall-clock budget
    with **partial-result resilience** — a hung engine is abandoned and the
    results already gathered are returned, with the timed-out engines named in
    the run label.
  - `ENGINE_NAV_TIMEOUT_SECONDS` (default 30) now drives `SearchEngine.timeout`.
  - Non-blocking executor shutdown + atexit browser guard = no zombie Chromium.
- Observability metrics: `concurrent_search_runs`, `engine_attempts`,
  `engine_success`, `engine_empty`, `engine_timeout`.
- `validate_config()` now checks the three new knobs and warns when the
  concurrent deadline is below the per-engine navigation timeout.
- 4 new governor tests (bounded-parallelism proof under load, deadline/partial-
  result proof, nav-timeout wiring, config validation).
- Documented all three knobs in `.env.example` and `README.md`.

### Guarantees
- **No regression**: all 135 prior tests pass unchanged. Suite now **139
  passing** offline.
