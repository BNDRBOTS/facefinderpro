# FaceHunter PRO — Independent Forensic Audit (Pass 3)

**Auditor:** BNDR (Notion AI)  **Date:** 2026-07-25  **Scope:** full A→Z review of
`FaceFinderPRO.py` (2,378 LOC), the three test suites, and all packaged docs.

> **Verification honesty.** This audit was performed in a sandbox with **no
> network access and no GPU**. What that means for the claims below:
>
> | Layer | How it was verified |
> |---|---|
> | Byte-compile of the whole module | ✅ `python -m py_compile` — passes |
> | Pure-logic suite (persistence, caches, SSRF guard, sanitizers, schema, backups, metrics, engines registry) | ✅ **127/127 executed and passing** via an offline pytest-compatible runner (numpy + Pillow present) |
> | Streamlit UI (`test_app_smoke.py`) | ⚠️ **Not executed** — `streamlit` cannot be installed offline. Static review only. |
> | InsightFace embeddings / face detection | ⚠️ **Not executed** — `insightface`/ONNX model not installable offline. Static review only. |
> | Playwright stealth automation against live engines | ⚠️ **Not executed** — no browser binaries / no network. Static review only. |
> | Live network fetch / real SSRF redirect behavior | ⚠️ Simulated with fakes; **not** exercised against a real server. |
>
> Do not read "127 passing" as "the whole product is proven." It proves the
> logic core. The ML, browser, and UI layers still need a run on a networked,
> GPU-capable host before you trust them in production.

## What I changed this pass

All fixes ship with regression tests in `tests/test_audit_pass3.py` (16 new
tests) and leave the existing 111 tests green.

### Correctness / security
1. **Redirect-based SSRF bypass (High).** `download_and_verify` fetched with
   `allow_redirects=True`, so a public candidate URL could `30x`-redirect the
   fetcher to `169.254.169.254` or `127.0.0.1` *after* `is_url_safe()` had
   already passed. Added `_ssrf_safe_request()`, which disables automatic
   redirects and re-validates **every hop** with `is_url_safe()`. Both HEAD and
   streamed GET now use it.
2. **IPv4-mapped IPv6 SSRF evasion (Medium).** `_is_blocked_ip()` did not
   unwrap `::ffff:169.254.169.254`. It now evaluates the embedded IPv4 address.
   (Also removed a duplicate `is_multicast` check.)
3. **`upgrade_image_url` discarded its work on failure (Medium, had a failing
   test).** On any HEAD/network error it returned the *un-enlarged* original,
   silently yielding low-resolution candidates. It now falls back to the
   size-upgraded URL. This is the single test that was **red before the audit**.
4. **Non-atomic byte-budget counter (Low).** The per-search `total_bytes`
   counter was mutated with `+=` across 10 worker threads; `+=` on a list
   element is not atomic under CPython. Now guarded by `_download_bytes_lock`,
   so the download budget cap is actually accurate.

### Sustainability (I/O)
5. **Cache backup amplification (Medium).** `EmbeddingCache`/`SearchCache`
   copied the entire pickle to a rotating `.bak` on *every* `set()` — O(n) per
   insert, O(n²) per search, times 10 workers. Caches are regenerable, so
   rotating backups were pure disk thrash and are removed. Corruption recovery
   still resets safely to an empty cache. **Gallery backups are kept** (that
   data is precious and not regenerable).
6. **SearchCache write on every miss (Low).** `get()` called `save()` on a
   plain cache miss, writing the whole pickle for a lookup that changed
   nothing. It now writes only when it actually evicts an expired entry.

### Robustness / privacy / UX
7. **`validate_config()` (new).** Startup sanity checks for the env knobs
   (negative caps, download cap > per-search budget, SSRF disabled). Warnings
   render in the sidebar instead of failing silently mid-search.
8. **Log-tail privacy redaction (Medium, privacy).** `_safe_log_tail()` (used
   by the diagnostic report) now strips URL paths and query strings, keeping
   only `scheme://host`. Candidate/source URLs identify *who* was searched;
   they no longer leak into a report. Credential redaction was already present.
9. **Stale pending-delete (Low).** `clear_results()` now clears
   `pending_delete`, so a reset can't leave a delete confirmation pointing at a
   name that no longer exists.

## Findings I did NOT silently "fix" — decisions for you

- **Gallery stores the *query* embedding, not the matched image's own
  embedding.** In both auto-save and the manual "Add to Gallery" path, the
  entry's `embedding` is the uploaded query's embedding while `full_image` is
  the matched result. That is internally inconsistent, but it may be intended
  ("a gallery of identities I searched for"). I left the behavior unchanged and
  am flagging it rather than guessing. Tell me which semantics you want and I
  will wire it up with tests.
- **DNS-rebinding TOCTOU remains partially open.** `is_url_safe()` resolves the
  hostname, then `requests` resolves it again at connect time; a hostile
  resolver could return a public IP to the check and a private IP to the fetch.
  The per-hop redirect fix closes the *redirect* vector; fully closing rebinding
  requires pinning the validated IP into the socket (custom adapter) or an
  egress firewall. Documented in `SECURITY.md`; not fixed here because it cannot
  be verified offline and warrants a networked test.
- **`pickle` persistence.** Even with the `_RestrictedUnpickler` + HMAC
  envelope, pickle remains a sharp tool. The restricted loader is solid (tested
  against `os.system`, `subprocess`, `eval`, `__import__`, unknown modules), but
  a JSON/SQLite store would remove the class of risk entirely. Recommendation,
  not a defect.

## Bolstering added to the package
- `SECURITY.md` — threat model, SSRF/pickle/telemetry posture, residual risks.
- `LEGAL_AND_PRIVACY.md` — biometric-law, ToS, and privacy considerations for a
  reverse **face** search tool. Read this before any real-world use.
- `Dockerfile` + `.dockerignore` — reproducible, pinned, non-root deployment.
- `Makefile` — `install` / `test` / `lint` / `run` / `docker` targets.
- `.gitignore` — keeps `face_data/`, backups, exports, and reports out of git.
- `CHANGELOG.md` — this pass, recorded.
- `tests/test_audit_pass3.py` — 16 new regression tests.
