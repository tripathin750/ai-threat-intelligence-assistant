# AI-Based Threat Intelligence Assistant
# Day 13 – NVD Ingestion Service

**Date:** 28 July 2026

---

# Objective

The objective of today's session was to turn the individual pieces built on Days 5–12 (NVD client, normalization, Pydantic validation, SQLAlchemy models) into a single, reliable ingestion service: `backend/services/ingestion_service.py`. The service fetches changed CVEs, validates every record, and atomically upserts them into PostgreSQL/SQLite, while recording synchronization state for incremental runs.

---

# Topics Studied

## Data Ingestion Service

An ingestion service collects data from an external source and imports it into the application's internal storage. `synchronize_nvd(db, limit)` in [ingestion_service.py](../backend/services/ingestion_service.py) is that component for this project:

```
NVD API → fetch_modified_cves() → normalize_cve() → Pydantic validation → upsert → PostgreSQL/SQLite
```

## Incremental Synchronization via `SyncState`

Rather than a naive full download, a dedicated `SyncState` table ([models.py](../backend/models.py)) stores `last_successful_sync` per source. Each call to `synchronize_nvd` reads the previous timestamp and asks the NVD API only for records modified since then (`fetch_modified_cves` in [fetch_cves.py](../backend/fetch_cves.py)), with a 5-minute overlap to avoid missing a record at the boundary and a 119-day cap so a stale sync state can still issue a valid request instead of failing outright.

## NVD Pagination

`fetch_modified_cves` / `fetch_latest_cves` page internally using `resultsPerPage=2000` and `startIndex`, looping until `totalResults` is satisfied, so callers never have to think about pagination.

## Duplicate Detection and Upsert

`cve_id` is the primary key on `Vulnerability`, so the database itself rejects a blind duplicate insert. The ingestion service handles this at the application level first:

```python
vulnerability = db.get(Vulnerability, record["cve_id"])
if vulnerability is None:
    db.add(Vulnerability(**record))
    created += 1
else:
    for field, value in record.items():
        setattr(vulnerability, field, value)
    updated += 1
```

This is a true upsert: an existing CVE is updated in place (its description, CVSS score, or CWE can legitimately change over time) instead of causing an integrity error or being silently skipped forever.

## Transactions and Rollback

All upserts for one sync run happen inside a single transaction. If any database operation raises `SQLAlchemyError`, `db.rollback()` discards the partial transaction and the exception is re-raised (and logged) rather than leaving the database half-updated.

## Logging

`backend/logging_config.py` configures a single, secret-free log format (`configure_logging()`, called once at startup in `main.py`). The ingestion and scheduler modules log with `logging.getLogger(__name__)` at `INFO` for normal activity and `exception(...)` for failures, never logging raw API keys or database credentials.

---

# Data Pipeline

```
NVD API
   │
   ▼
fetch_modified_cves(last_successful_sync)   # paginated internally
   │
   ▼
normalize_cve() for each record             # extraction + normalization
   │
   ▼
VulnerabilitySchema.model_validate()        # Pydantic validation
   │
   ▼
db.get(Vulnerability, cve_id) → UPDATE or INSERT   # upsert
   │
   ▼
commit() / rollback() as one transaction
   │
   ▼
SyncState.last_successful_sync updated
```

---

# Practical Activities

- Implemented `synchronize_nvd()` combining fetch → normalize → validate → upsert in one transaction.
- Added the `SyncState` model and incremental (`lastModStartDate`/`lastModEndDate`) synchronization instead of full re-downloads.
- Confirmed pagination inside `fetch_modified_cves`/`fetch_latest_cves` handles more than one NVD page.
- Verified duplicate CVEs update existing rows instead of erroring or duplicating (`created`/`updated` counters in `SyncResultSchema`).
- Wired rollback-on-error and centralized logging.
- Exposed the service through `POST /cves/sync?limit=...` in `main.py`, protected by the optional API-key dependency.

---

# Testing Performed

Ran the ingestion pipeline live against the real NVD API with a local SQLite database:

```
POST /cves/sync?limit=20  →  {"fetched":20,"validated":20,"skipped":0,"created":20,"updated":0}
```

Re-running the same sync call did not create duplicate rows — the second run's `created` count was 0 and `updated` reflected any records whose data had changed, confirming the upsert logic.

---

# Key Learnings

- Ingestion and consumption (search/read) should be separate concerns — the dashboard never blocks on an NVD network call.
- Incremental sync via a stored `last_successful_sync` timestamp is dramatically cheaper than re-fetching the whole dataset, and NVD's `lastModStartDate`/`lastModEndDate` parameters are built for exactly this.
- Application-level upsert logic (check-then-insert-or-update) turns duplicate CVEs into an intentional update path rather than a database error.
- A transaction boundary around the whole batch keeps the database consistent if one record in the middle fails.
- Logging must be structured and free of secrets from day one, not bolted on later.

---

# Security Considerations

The NVD API is an external trust boundary: every record still passes through `normalize_cve()` and `VulnerabilitySchema` before it can reach the database, regardless of how much the API is trusted. `verify_api_key` optionally protects the sync endpoint from unauthenticated triggering, and `RateLimitMiddleware` bounds how often it can be called. Logs record counts and outcomes, never credentials or full raw payloads.

---

# Reflection

The ingestion service is the piece that makes this an actual pipeline rather than a set of disconnected scripts. Building duplicate handling and incremental sync in from the start avoids a rewrite later and keeps repeated ingestion runs cheap and safe — which matters once the scheduler (Day 16) starts calling this automatically.

---

# Next Steps

- Expose search and filtering over the ingested data (`GET /cves`) — Day 14.
- Harden error handling around NVD outages with explicit HTTP status mapping — Day 15.
- Automate `synchronize_nvd()` on an interval — Day 16.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why store `SyncState` instead of always fetching "the last 24 hours"?**

✅ A fixed lookback window either re-fetches data unnecessarily (wasteful) or misses changes if the gap between runs is longer than the window (unsafe). Storing the actual last successful sync time lets each run ask NVD for exactly what changed since then, with a small overlap for safety.

**2. Why upsert instead of "insert, ignore duplicates"?**

✅ CVE records are not static — CVSS scores, descriptions, and CWE classifications can be revised after publication. Ignoring an existing CVE would leave the local database permanently out of date.

**3. What does `db.rollback()` protect against here?**

✅ If record 40 of 100 fails to insert due to a database error, rollback prevents the first 39 inserts of that same transaction from being committed as a half-finished, inconsistent batch.

---

# 🎤 Interview Questions

**Q1. Why is ingestion triggered by its own endpoint/scheduler instead of on every `/cves` request?**
Coupling ingestion to read requests would make the API's latency and reliability depend on NVD's availability. Separating them lets the dashboard read quickly from local storage while ingestion runs independently and can fail/retry on its own schedule.

**Q2. How does this design tolerate a partial NVD outage mid-sync?**
`fetch_modified_cves` raises `NVDRequestError` before any database writes happen, so a network failure simply aborts the sync with nothing written — `SyncState` is only updated after a successful commit, so the next run correctly retries from the last known-good timestamp.

---

# ⚡ 5-Minute Revision

- Ingestion service → collects, validates, and stores external data.
- Incremental sync → only fetch what changed since `last_successful_sync`.
- Upsert → update if `cve_id` exists, insert if it doesn't.
- Transaction → all-or-nothing; `rollback()` undoes a failed batch.
- Logging → structured, secret-free, essential for debugging a pipeline that runs unattended.
