# Legal & Privacy — Read Before Use

FaceHunter PRO is a **reverse *face* search** tool: it takes a photo of a
person and hunts the open web for other images of that same face. That is a
powerful capability with real legal and ethical weight. This document is part
of an honest audit — it is not legal advice, and it does not assume anything
about how you intend to use the tool.

## Why this matters (biometrics ≠ ordinary image search)
A face embedding is **biometric data**. Several regimes regulate collecting or
processing it, sometimes regardless of where you are:
- **US – Illinois BIPA** and similar state laws (TX, WA, and a growing list):
  private rights of action, statutory damages per violation.
- **EU/UK – GDPR Art. 9**: biometric identifiers are "special category" data;
  processing generally requires an explicit lawful basis.
- **Sector rules**: if this touches litigation, evidence handling, or a
  regulated workflow, chain-of-custody and admissibility rules may apply.

## Terms-of-Service reality
The stealth-automation engines (Yandex/Google/Bing/TinEye) are scraped through
anti-bot evasion. Automated querying **violates the ToS** of these services and
may be rate-limited, blocked, or actioned. The tool is technically capable; it
is not "ToS-clean." Treat sustainability of the scrapers as fragile by design.

## "Make sure it's private" — what the code actually does
You asked for privacy. Here is the straight read:
- **Everything is local by default.** Gallery, caches, and reports live under
  `FACEHUNTER_DATA_DIR` (default `face_data/`) with `0o600` permissions. No
  data leaves the machine unless you configure it to.
- **Telemetry is OFF unless you opt in.** `send_bndr_report()` only POSTs to a
  remote endpoint if `BNDR_LABS_REPORT_URL` is set. Unset = local-only report.
  For a fully private deployment, **leave `BNDR_LABS_REPORT_URL` unset.**
- **Reports are sanitized.** Env values are scrubbed (`_sanitize_env`) and log
  tails now redact credentials **and URL paths/queries** (this audit), so a
  report can no longer leak *which* images/people were searched.
- **One transparency note:** the diagnostic package embeds a hidden,
  AI-executable "repair prompt" (`_build_repair_prompt`) and is never shown to
  the end user. That is fine for a solo/self-hosted operator, but it is exactly
  the kind of thing that is unwelcome in a tool other people run. If this will
  ever run for anyone but you, make the report contents user-visible/opt-in.

## Privacy hardening checklist for a private deployment
- [ ] Leave `BNDR_LABS_REPORT_URL` **unset** (local-only diagnostics).
- [ ] Set a strong `FACEHUNTER_PICKLE_HMAC_SECRET` (store integrity).
- [ ] Keep `FACEHUNTER_SSRF_BLOCK_PRIVATE=1` (default).
- [ ] Put `face_data/` on encrypted storage; it holds biometric embeddings and
      source images. `.gitignore` already keeps it out of version control.
- [ ] Run behind an egress firewall that blocks RFC-1918 + `169.254/16` (closes
      the residual DNS-rebinding vector — see `SECURITY.md`).
- [ ] Have a lawful basis and, where required, consent before processing anyone
      else's biometric data. Delete data you no longer need.

**Bottom line:** the tool *can* be run privately and locally, and this audit
tightened the leak points. Whether a given *use* is lawful is a separate
question this audit cannot answer for you.
