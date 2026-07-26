# Security Posture — FaceHunter PRO

## Threat model
The app takes an **untrusted uploaded image**, drives **untrusted third-party
search engines**, and fetches **untrusted candidate URLs** off the open web,
then persists results to disk. Every one of those boundaries is treated as
hostile.

## Controls in place
| Risk | Control | Tested |
|---|---|---|
| SSRF to internal/loopback/metadata | `is_url_safe()` + `_is_blocked_ip()` (private, loopback, link-local, reserved, multicast, unspecified, **IPv4-mapped IPv6**), enforced on the initial URL **and every redirect hop** via `_ssrf_safe_request()` | ✅ |
| Decompression bombs | `safe_open_image()` enforces byte cap, pixel cap (`MAX_IMAGE_PIXELS`), and dimension cap before decode | ✅ |
| Oversized downloads | HEAD `Content-Length` pre-check + streamed byte cap + per-search total-bytes budget (lock-guarded) | ✅ |
| Pickle RCE | `_RestrictedUnpickler` allowlist (blocks `os.system`, `subprocess`, `eval`, `__import__`, unknown modules) | ✅ |
| Store tampering | Optional HMAC envelope (`FACEHUNTER_PICKLE_HMAC_SECRET`); tampered stores fall back to default, never execute | ✅ |
| Path traversal | `sanitize_gallery_name()` strips separators/null bytes, caps length | ✅ |
| Metadata injection | `_sanitize_metadata()` coerces types and caps key/value length | ✅ |
| Data loss | Atomic writes (`_atomic_pickle_write`), rotating Gallery backups, corrupt-store quarantine + restore | ✅ |
| Credential/PII leakage in reports | `_sanitize_env()` + `_safe_log_tail()` redacts credentials **and URL paths/queries** | ✅ |

## Residual risks (accept, monitor, or close before production)
1. **DNS rebinding (TOCTOU).** `is_url_safe()` and the actual fetch resolve DNS
   independently. A hostile resolver can pass validation then serve a private
   IP. **Mitigation options:** pin the validated IP into a custom
   `requests` adapter, or run the fetcher behind an egress firewall / no route
   to RFC-1918 + `169.254.0.0/16`. Not closed in code because it cannot be
   verified offline.
2. **Pickle at rest.** Restricted + HMAC-guarded, but migrating the gallery and
   caches to JSON/SQLite would remove the risk class entirely.
3. **Telemetry / `send_bndr_report`.** Off by default (no endpoint configured =
   local-only). If you set `BNDR_LABS_REPORT_URL`, sanitized diagnostics are
   POSTed off-box. See `LEGAL_AND_PRIVACY.md`. Keep it unset for a fully local,
   private deployment.
4. **Stealth automation is inherently brittle & adversarial.** Engines change
   markup and anti-bot logic without notice; treat scraper breakage as a
   *when*, not an *if*, and keep the `requests`-based Yandex fallback current.

## Reporting
This is a private tool. If you extend it and find a security issue, fix it on a
branch, add a regression test under `tests/`, and record it in `CHANGELOG.md`.
