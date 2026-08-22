# AI-Based Threat Intelligence Assistant
# Day 15 – Error Handling & Logging

**Date:** 30 July 2026

---

# Objective

Make the backend fail safely instead of crashing or leaking internals when something goes wrong — an unreachable NVD API, a database outage, or simply a bad request. This is implemented across [backend/main.py](../backend/main.py), [backend/security.py](../backend/security.py), and [backend/logging_config.py](../backend/logging_config.py).

---

# Topics Studied

## The Three Places Things Go Wrong

1. **The external API** (NVD) can be slow, down, or return malformed JSON.
2. **The database** can be unreachable or reject a write.
3. **The client** can send an invalid CVE ID, an out-of-range CVSS filter, or a request that exceeds a limit.

Each needs a different response, and none of them should ever surface a Python stack trace to the caller.

## Custom Exception Types, Not Bare Exceptions

```python
class NVDRequestError(RuntimeError):
    """Raised when the NVD API cannot be queried successfully."""

class VulnerabilityValidationError(ValueError):
    """Raised when a normalized record is unsafe to store."""
```

Defining specific exception classes (in [fetch_cves.py](../backend/fetch_cves.py)) means route handlers can catch precisely what they expect and let anything truly unexpected propagate — rather than swallowing every exception with a bare `except Exception:`, which would hide real bugs.

## Mapping Exceptions to HTTP Status Codes

```python
@app.get("/cves/live", ...)
def get_live_cves(limit: int = Query(default=5, ge=1, le=100)):
    try:
        payload = fetch_latest_cves(limit)
        return _extract_valid_records(payload)[0]
    except NVDRequestError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="NVD is unavailable.") from exc
```

`502 Bad Gateway` is the correct status here: the client's request to *our* API was fine, but the upstream service (NVD) failed. This distinction — is the fault ours, the client's, or upstream's — is what HTTP status codes exist to communicate. `POST /cves/sync` does the same mapping.

## A Global Handler for Database Failures

```python
@app.exception_handler(SQLAlchemyError)
async def database_exception_handler(_: Request, exc: SQLAlchemyError) -> JSONResponse:
    logger.exception("database request failed", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "A database operation could not be completed."},
    )
```

Rather than repeating a `try/except SQLAlchemyError` in every single route, FastAPI's `@app.exception_handler` registers one handler that catches it application-wide. The client always gets a generic, safe message; the *real* exception (with full traceback) goes only to the server log via `logger.exception(...)`.

## What Must Never Reach the Client

- Database connection strings or credentials
- Full stack traces
- Internal file paths
- Raw SQL

`database_exception_handler` above demonstrates the pattern: log everything internally, return only `{"detail": "A database operation could not be completed."}` externally.

## Validation Errors Are Already Handled — By Design, Not Accident

A malformed `cve_id` or an out-of-range `min_cvss` never reaches a route body at all: FastAPI/Pydantic reject it during request parsing and return `422 Unprocessable Entity` with a structured error automatically. This is the same input-validation-at-the-boundary principle from Day 12, just visible now as an error-handling behavior rather than a schema definition.

## Rate Limiting as Defensive Error Handling

```python
class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        ...
        if len(window) >= self.requests_per_minute:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again in a minute."})
```

A `429 Too Many Requests` response, returned *before* the request reaches any route, is also a form of graceful failure: it protects the NVD API and the database from being hammered by a runaway client or script, rather than letting the failure cascade into a database connection-pool exhaustion or an NVD ban.

---

# Practical Activities / Testing Performed

- Added `backend/tests/test_api.py::test_get_cve_rejects_a_malformed_id_before_touching_the_database` — confirms a malformed CVE ID returns `422`, not a crash.
- Added `backend/tests/test_api.py::test_get_cve_by_id_and_404_for_unknown` — confirms a well-formed but nonexistent CVE ID returns `404`, not `500`.
- Added `backend/tests/test_api.py::test_zz_rate_limit_returns_429_once_the_window_is_exceeded` — drives the real configured `RATE_LIMIT_PER_MINUTE` past its limit and confirms `429`.
- Manually verified `POST /cves/sync` returns `502 Bad Gateway` rather than crashing when the NVD host is unreachable, by pointing `NVD_URL`-equivalent traffic at a closed port during local testing.

---

# Key Learnings

- Different failure sources (client input, our database, an upstream API) deserve different, specific HTTP status codes — not a blanket 500.
- A single, centralized exception handler for a whole exception *class* (`SQLAlchemyError`) is more reliable than repeating try/except in every route.
- The message returned to the client and the information written to the log should be different: generic outward, detailed inward.
- Rate limiting is itself an error-handling strategy — it turns "the database falls over under load" into a controlled, immediate `429`.

---

# Security Considerations

Verbose error messages are a genuine information-disclosure risk: a raw SQLAlchemy exception can reveal table names, column names, or even connection details. Every error path in this project was checked against that principle — the client-facing message is always a short, generic string, and detail only ever goes to `logger.exception(...)`, which itself is configured (Day 13) to never log secrets.

---

# Reflection

Error handling is easy to skip while a project only ever runs against a live NVD API and a healthy local database — everything "just works." It only becomes visible once something upstream fails, at which point the difference between a clean `502` and an unhandled stack trace is the difference between a professional API and a broken one. Building this in now, rather than after a real outage, is what makes the ingestion scheduler (Day 16) safe to run unattended.

---

# Next Steps

- Automate `synchronize_nvd()` on an interval so ingestion doesn't depend on a manual call (Day 16).
- Extend structured logging with request correlation IDs for tracing one request across log lines (`X-Request-ID` is already generated by `RateLimitMiddleware` — Day 16+ can start threading it through logger calls).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why is `502 Bad Gateway` more correct than `500` when NVD is down?**
✅ `500` implies our own server failed to process a valid request; `502` correctly signals that *we* were fine but a service we depend on (NVD) failed — useful information for anyone debugging the outage.

**2. Why use a global `@app.exception_handler` instead of try/except in every route?**
✅ It guarantees consistent behavior for that exception type everywhere, and it means a route author can't forget to handle it — the safety net exists at the framework level, not per-endpoint.

**3. Why shouldn't error responses include the raw exception message?**
✅ It can leak internal details (table/column names, file paths, library versions) that help an attacker understand the system. A short, generic client-facing message plus a detailed internal log gives developers what they need without exposing it externally.

---

# 🎤 Interview Questions

**Q1. How does this API distinguish "the request was invalid" from "our system failed"?**
Client-side problems (malformed CVE ID, out-of-range parameter) are caught by Pydantic/FastAPI validation and return `4xx` before any application code runs. Server- or upstream-side problems (database error, NVD outage) are caught explicitly and mapped to `500`/`502` with a logged root cause.

**Q2. What's the risk of a bare `except Exception: pass` in a route handler?**
It silently swallows *every* failure, including bugs that should be visible and fixed — a genuine data-corruption bug could hide behind the same handler as a harmless network timeout. Catching specific exception types keeps failure modes distinguishable.

---

# ⚡ 5-Minute Revision

- Custom exception classes → let route code catch precisely what it expects.
- `502` → our service is fine, upstream failed. `500` → our service failed. `422` → the caller's request was invalid.
- Global exception handlers → one place to guarantee consistent, safe behavior for a whole exception class.
- Generic message outward, full detail only in the log.
- Rate limiting → error handling applied *before* the failure (429 instead of an overloaded backend).

---

# 🔐 Security Concept of the Day

**Fail Securely.** A system that crashes or leaks internals under failure is itself a vulnerability. Every error path here was designed to answer two questions before being written: *what does the client need to know*, and *what must never leave this process*.
