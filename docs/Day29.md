# AI-Based Threat Intelligence Assistant
# Day 29 – Security Testing & TTPs

**Date:** 13 August 2026

---

# Objective

Perform an actual security review of the running application — not just a theory recap — covering the OWASP-relevant areas from the original brief (input validation, injection, authentication, secrets, dependency vulnerabilities, rate limiting, secure headers), and clearly separate two things this project has, so far, kept distinct on purpose: **attacker TTPs** (MITRE ATT&CK — what the *system studies*) versus **defensive security controls** (what the *system implements to protect itself*).

---

# Topics Studied

## Attacker TTPs vs. This Project's Own Security Controls

This is a distinction worth stating explicitly, because it's easy to conflate them:

| | MITRE ATT&CK TTPs | This project's defensive controls |
|---|---|---|
| What it is | Tactics/Techniques/Procedures *adversaries* use | Practices *this application* uses to defend itself |
| Example | T1190 – Exploit Public-Facing Application | Input validation on every route parameter |
| Where it lives in this project | `backend/data/attack_catalog.py`, inferred against ingested CVEs | `backend/security.py`, `backend/main.py` exception handling, `backend/schemas.py` |
| Role | Subject the system *analyzes* | Practices the system *follows* |

The application both studies attacker TTPs (as data, about CVEs it ingests) and implements its own defensive controls (as code, protecting itself) — these are not the same axis, and a report or dissertation chapter should never present a defensive control ("we validate input") as if it were an ATT&CK technique, or vice versa.

## OWASP-Style Review Performed

**Injection (SQL).** Every database filter goes through SQLAlchemy's parameterized expression API (`Vulnerability.severity == value`, `.ilike(term)`) — confirmed on Day 14, re-confirmed here: there is no raw SQL string concatenation with user input anywhere in the codebase (`grep`-verified: `text(...)` is used exactly once, for `SELECT 1` in `/health`, with no interpolated input).

**Broken authentication / weak comparison.** `verify_api_key` uses `hmac.compare_digest(supplied, settings.api_key)` (`security.py`) — a constant-time comparison, which prevents a timing side-channel from being used to guess the key one byte at a time. A naive `==` comparison would have been a real, if subtle, vulnerability.

**Sensitive data exposure.** Logging is centrally configured and never logs request bodies, headers, or credentials (Day 13); error responses return generic messages, never raw exceptions (Day 15). **Finding**: a stray `.env` file at the project root contains a real local PostgreSQL password in plaintext. It is `.gitignore`d and not actually read by the application (`backend/config.py` only loads `backend/.env`, which doesn't exist), so it isn't a live exposure risk today — but it's an unused credential sitting in the repo tree and should be deleted or moved outside the project directory rather than left in place.

**Security misconfiguration.** `ALLOWED_HOSTS` defaults to `"*"`, which means `TrustedHostMiddleware` is skipped entirely by default (`main.py`: `if settings.allowed_hosts != ("*",): app.add_middleware(...)`). This is a reasonable default for local development but should be set explicitly to the real deployment hostname(s) in any non-local environment — otherwise the app accepts any `Host` header, which matters for things like Host-header-based cache poisoning or link generation in a future feature. **Finding, not yet fixed** — a configuration decision for deployment, not a code bug.

**Missing security headers.** **Finding, fixed this session**: the app previously set no baseline security headers. Added `SecurityHeadersMiddleware` (`security.py`) setting `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cross-Origin-Opener-Policy: same-origin` on every response, verified live and covered by `test_api.py::test_security_headers_present_on_every_response`.

**Rate limiting / resource exhaustion.** `RateLimitMiddleware` bounds requests per client per minute; confirmed both by code review and by `test_api.py::test_zz_rate_limit_returns_429_once_the_window_is_exceeded`, which drives the real configured limit and confirms `429`. **Known limitation, documented not fixed**: the limiter is in-memory and per-process (a comment in `security.py` already says so) — it would need shared storage (e.g. Redis) to work correctly behind multiple worker processes or instances, which is out of scope for this MVP's single-process deployment model.

**XSS.** Backend is a JSON API (no HTML templating with user data); the dashboard renders every API-sourced value via `textContent`, never `innerHTML` (Day 28) — verified by code review of every DOM-writing line in `frontend/app.js`.

**Vulnerable/outdated dependencies.** Ran `pip-audit` against `backend/requirements.txt`: **no known vulnerabilities found** in the current dependency set (fastapi, pydantic, psycopg[binary], python-dotenv, requests, SQLAlchemy, uvicorn[standard], httpx).

**Input validation at every boundary.** Re-confirmed end-to-end: NVD JSON → `normalize_cve()` + `VulnerabilitySchema` (Day 11–12); every API path/query parameter → FastAPI/Pydantic constraints (Day 14); reject-unexpected-fields (`extra="forbid"`) on the public schema so a client can never smuggle an unexpected field through validation.

## Summary of Findings

| Finding | Status |
|---|---|
| No baseline security headers | **Fixed** — `SecurityHeadersMiddleware` added |
| `POST /intelligence/{cve_id}/analyze` 500s on a fresh CVE | **Fixed** — `.populate_existing()` (Day 21) |
| Stray plaintext-password `.env` at project root, unused by the app | **Flagged** — recommend deleting/relocating; not auto-deleted without owner confirmation |
| `ALLOWED_HOSTS=*` default disables `TrustedHostMiddleware` | **Flagged** — set explicitly for any non-local deployment |
| Rate limiter is per-process, in-memory | **Documented limitation** — acceptable for single-process MVP; needs shared storage to scale |
| Dashboard has no way to supply `X-API-Key` | **Flagged** (Day 28) — relevant only if `API_KEY` is enabled for a deployment |
| Dependency vulnerabilities | **None found** (pip-audit, this session) |

---

# Practical Activities / Testing Performed

- Ran `pip-audit -r backend/requirements.txt` — clean.
- Manually reviewed every database query in the codebase for raw SQL/string interpolation of user input — none found outside the parameterized `text("SELECT 1")` health check.
- Manually reviewed every `frontend/app.js` DOM write for `innerHTML` usage — none found; all use `textContent`/`createElement`.
- Added and ran `test_security_headers_present_on_every_response` and `test_zz_rate_limit_returns_429_once_the_window_is_exceeded`.
- Ran the full test suite (32 tests across `test_api.py`, `test_ingestion.py`, `test_services.py`, `test_prompts.py`, `test_schemas.py`, `test_fetch_cves.py`) — all passing.

---

# Key Learnings

- ATT&CK TTPs (what a project studies about adversaries) and application security controls (what a project does to defend itself) are two different axes and should never be conflated in a report — this project happens to do both, which makes the distinction easy to blur if not stated explicitly.
- A constant-time comparison for secret verification (`hmac.compare_digest`) is a small, easy-to-miss detail with a real security consequence.
- A dependency scan is cheap to run and catches an entire class of risk (known CVEs in libraries) that no amount of application-level code review would find.
- "Flagged but not auto-fixed" is a legitimate, honest outcome for findings that are deployment/configuration decisions (host allowlist, stray credential file) rather than code defects — they need an owner's decision, not a unilateral change.

---

# Security Considerations

This entire day *is* the security-considerations exercise — its output (the findings table above) is the artifact. The two fixes applied (security headers, the intelligence-pipeline bug) were low-risk, additive, and fully covered by new regression tests before being considered done.

---

# Reflection

Running an actual review against the live, working system — rather than reasoning about security only in the abstract — is what surfaced genuinely actionable findings (the missing headers, the stray `.env` file) instead of a generic checklist recitation. Distinguishing ATT&CK TTPs from this project's own defensive controls also clarified something that matters for the dissertation's framing: this system is a *consumer and interpreter* of attacker TTP data, not itself demonstrating attacker TTPs.

---

# Next Steps

- Final functional/API/evaluation testing pass and results write-up (Day 30).
- Owner decision needed: delete or relocate the root `.env` file; set `ALLOWED_HOSTS` explicitly before any non-local deployment.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Give one example each of an ATT&CK TTP and a defensive control this project implements, and explain the difference.**
✅ TTP: T1190, Exploit Public-Facing Application — describes something an *attacker* does, and this project may infer it applies to a given CVE. Defensive control: `hmac.compare_digest()` for API key verification — something *this application* does to protect itself. One describes adversary behavior; the other describes the system's own defense.

**2. Why is `hmac.compare_digest()` used instead of `==` to check the API key?**
✅ A standard `==` comparison on strings short-circuits at the first mismatched character, making the comparison time subtly dependent on how many leading characters are correct — an attacker measuring response times could exploit that to guess the key incrementally. `compare_digest()` runs in constant time regardless of where the mismatch occurs.

**3. Why flag the root `.env` file instead of deleting it directly?**
✅ It's a credential file the reviewer didn't create and isn't certain is unused by every workflow (e.g. a human might use it manually with `psql` outside the app) — deleting a credential without the owner's confirmation risks losing something they still rely on, even though the running application itself doesn't read it.

---

# 🎤 Interview Questions

**Q1. How would you explain to a non-technical stakeholder why "the system maps CVEs to MITRE ATT&CK techniques" and "the system is built securely" are two separate claims?**
The first is about what the system *knows and can explain* to a defender — it's a feature, describing adversary behavior as data. The second is about whether the system *itself* resists being attacked — authentication, input validation, rate limiting, secure secret handling. A system could do the first well and still be insecure, or vice versa; they need to be evaluated independently.

**Q2. `pip-audit` reports no known vulnerabilities today. What does that guarantee, and what doesn't it guarantee?**
It guarantees the currently pinned dependency versions have no *publicly disclosed* vulnerabilities in the advisory database it checks, as of today. It does not guarantee the absence of unknown ("zero-day") vulnerabilities, and the result can change the moment a new CVE is published against one of these libraries — dependency scanning needs to be a recurring practice, not a one-time check.

---

# ⚡ 5-Minute Revision

- ATT&CK TTPs = what adversaries do (data the system studies). Security controls = what this app does to defend itself (code the system runs).
- `hmac.compare_digest()` → constant-time secret comparison, prevents timing attacks.
- SQLAlchemy's expression API → the actual SQL-injection defense, verified by code review.
- `textContent` over `innerHTML` → the actual XSS defense on the frontend.
- `pip-audit` → cheap, catches a whole class of risk unit tests can't.
- Findings this session: security headers added (fixed), stray `.env` and `ALLOWED_HOSTS=*` flagged (owner decision needed).
