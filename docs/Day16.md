# AI-Based Threat Intelligence Assistant
# Day 16 – Automated NVD Synchronization

**Date:** 31 July 2026

---

# Objective

Stop depending on a manually triggered `POST /cves/sync` call. Implement a background scheduler that runs the ingestion pipeline on an interval, entirely from the standard library, so the local vulnerability store stays current without operator intervention. Implemented in [backend/services/scheduler.py](../backend/services/scheduler.py) and wired into the app lifespan in [backend/main.py](../backend/main.py).

---

# Topics Studied

## Background Jobs Inside a Single-Process App

For an MVP that doesn't yet need a distributed task queue (Celery, RQ), a daemon thread is a legitimate, low-complexity way to run a periodic job inside the same process as the API:

```python
class NvdSyncScheduler:
    def __init__(self, interval_minutes: int) -> None:
        self._interval_seconds = interval_minutes * 60
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        self._thread = Thread(target=self._run, name="nvd-sync", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval_seconds):
            db = SessionLocal()
            try:
                synchronize_nvd(db)
                logger.info("scheduled NVD sync completed")
            except Exception:
                logger.exception("scheduled NVD sync failed")
            finally:
                db.close()
```

## `Event.wait()` Instead of `time.sleep()`

`self._stop_event.wait(self._interval_seconds)` sleeps for the interval *unless* `stop()` sets the event first, in which case it returns immediately. Using `time.sleep()` instead would ignore a shutdown signal and force the process to wait out the full interval before exiting cleanly — `Event.wait()` makes shutdown responsive.

## Daemon Threads and Graceful Shutdown

`daemon=True` ensures the thread cannot keep the process alive if the main app exits unexpectedly. `stop()` still explicitly signals and joins the thread (with a timeout) during the app's lifespan shutdown, so a normal shutdown is clean rather than relying solely on daemon-thread semantics:

```python
@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    ...
    scheduler = NvdSyncScheduler(settings.sync_interval_minutes) if settings.enable_scheduler else None
    if scheduler:
        scheduler.start()
    yield
    if scheduler:
        scheduler.stop()
```

## Wait First, Not Sync First

The loop waits for the interval *before* the first sync (`while not self._stop_event.wait(...)`), not after. This is deliberate: application startup stays fast regardless of `SYNC_INTERVAL_MINUTES`, and an operator who wants data immediately can still call `POST /cves/sync` directly — the scheduler doesn't block or duplicate that path.

## One Session Per Scheduled Run, Not a Shared One

Each iteration creates its own `SessionLocal()` and closes it in `finally`, exactly like the `get_db()` request dependency. A background thread must manage its own session lifecycle explicitly since there's no request/response cycle to hook into.

## Configuration, Not Hardcoding

```python
enable_scheduler: bool = os.getenv("ENABLE_SCHEDULER", "false") in {"1", "true", "yes"}
sync_interval_minutes: int = max(5, int(os.getenv("SYNC_INTERVAL_MINUTES", "60")))
```

The scheduler is opt-in (`ENABLE_SCHEDULER=false` by default) so running the test suite or a quick local `uvicorn` session never starts unwanted background network calls, and the interval has a floor of 5 minutes so a misconfiguration can't hammer the NVD API.

## Failure Isolation

A single failed sync (`except Exception: logger.exception(...)`) does not stop the loop — the next scheduled attempt still runs. An ingestion job that dies permanently after one NVD hiccup would silently stop updating the entire application until someone noticed and restarted it.

---

# Architecture

```
App startup (lifespan)
        │
        ▼
ENABLE_SCHEDULER=true?
        │ yes
        ▼
NvdSyncScheduler.start()  (daemon thread)
        │
        ▼
   loop: wait(interval) → synchronize_nvd(db) → log outcome → repeat
        │
        ▼
App shutdown (lifespan) → scheduler.stop() → thread joined
```

---

# Practical Activities / Testing Performed

- Verified `ENABLE_SCHEDULER=false` (the default) starts the app with no background thread and no unexpected NVD calls, confirmed via `backend/tests/test_api.py` setting `ENABLE_SCHEDULER=false` explicitly before importing the app.
- Manually ran with `ENABLE_SCHEDULER=true` and `SYNC_INTERVAL_MINUTES=5` locally and confirmed a log line (`scheduled NVD sync completed`) appears after the interval elapses, and that `Ctrl+C` shuts the process down promptly (confirming `stop()`/`Event.wait()` interrupt correctly rather than blocking for the remainder of the interval).

---

# Key Learnings

- A daemon thread with `Event.wait()` is a proportionate solution for a single-process MVP's background job — no external task queue infrastructure needed yet.
- "Wait first" keeps startup fast and avoids surprising an operator with an immediate, uncontrolled sync.
- Background jobs need their own explicit session lifecycle; there's no framework dependency injection to rely on outside a request.
- One failed iteration must not kill the whole scheduled job — isolate and log, then continue.
- Feature-flagging background jobs (`ENABLE_SCHEDULER`) keeps test runs and local development deterministic and network-free by default.

---

# Security Considerations

The scheduler runs with the same database credentials and NVD API key as the rest of the application — no elevated privilege. Its failures are logged the same secret-free way as every other component (Day 13), and because it's opt-in and interval-floored, it can't be misconfigured into an accidental denial-of-service against the NVD API.

---

# Reflection

This is a small amount of code with an outsized effect: it's the difference between "a demo that needs a person to run a script" and "a system that keeps itself current." Because Days 13–15 already made `synchronize_nvd()` transactional, idempotent (upsert), and exception-safe, wiring a scheduler around it required no changes to the ingestion logic itself — a good sign that the earlier layering was done correctly.

---

# Next Steps

- Move from a rule-based analysis stub toward the AI summarization layer (Day 17–18).
- Consider request correlation IDs threaded from `RateLimitMiddleware`'s `X-Request-ID` into scheduled-job log lines, so a specific sync run can be traced end-to-end.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why `Event.wait(interval)` instead of `time.sleep(interval)` in the loop?**
✅ `Event.wait()` returns immediately if `stop()` sets the event, so shutdown is responsive; `time.sleep()` would ignore the stop signal and force a full wait before the thread could exit.

**2. Why does the loop wait before the first sync, not after?**
✅ So application startup time doesn't depend on `SYNC_INTERVAL_MINUTES`, and so the scheduler doesn't duplicate an operator-triggered `POST /cves/sync` immediately at boot.

**3. Why is the scheduler feature-flagged off by default?**
✅ So running tests or a quick local server never triggers unexpected background network calls to the real NVD API — background jobs should be opt-in during development.

---

# 🎤 Interview Questions

**Q1. Why a daemon thread instead of, say, Celery or APScheduler for this project?**
For a single-process MVP with one periodic job, an external task queue adds real operational complexity (broker, worker process, monitoring) for no corresponding benefit yet. A daemon thread with a clean start/stop lifecycle is proportionate; migrating to a dedicated scheduler becomes worthwhile once there are multiple jobs, multiple processes, or a need for guaranteed delivery.

**Q2. What happens if two application instances both run this scheduler against the same database?**
Both would attempt `synchronize_nvd()` independently. Because upserts are idempotent and keyed by `cve_id`, this is safe from a data-correctness standpoint (no duplicates), though it's redundant NVD traffic — in a multi-instance deployment, ingestion should be pulled out into a single dedicated worker rather than run per API instance.

---

# ⚡ 5-Minute Revision

- Daemon thread + `Event.wait()` → simple, responsive background job for a single process.
- Wait-first loop → fast startup, no surprise immediate sync.
- Own session per iteration → background jobs manage their own DB lifecycle.
- Isolate failures per iteration → one bad run doesn't kill the schedule.
- Feature flag + interval floor → safe defaults for tests and misconfiguration.
