"""Optional background NVD synchronization using only the standard library."""

import logging
from threading import Event, Thread

from ..database import SessionLocal
from .ingestion_service import synchronize_nvd


logger = logging.getLogger(__name__)


class NvdSyncScheduler:
    def __init__(self, interval_minutes: int) -> None:
        self._interval_seconds = interval_minutes * 60
        self._stop_event = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = Thread(target=self._run, name="nvd-sync", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Wait first: app startup must remain fast and an operator can trigger
        # a sync through the API immediately if desired.
        while not self._stop_event.wait(self._interval_seconds):
            db = SessionLocal()
            try:
                synchronize_nvd(db)
                logger.info("scheduled NVD sync completed")
            except Exception:
                logger.exception("scheduled NVD sync failed")
            finally:
                db.close()
