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
