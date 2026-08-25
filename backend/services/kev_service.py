"""Transactional CISA KEV ingestion with validation and upserts.

Unlike NVD ingestion (services/ingestion_service.py), CISA's feed has no
"changed since" query - every sync fetches and validates the full ~1,700-
entry catalogue and upserts all of it. SyncState (source="CISA_KEV") is
reused purely for observability (last attempt/success, record count), not
for any windowing logic.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..fetch_kev import KevValidationError, fetch_kev_catalog, normalize_kev_entry
from ..models import KevEntry, SyncState


logger = logging.getLogger(__name__)

KEV_SOURCE = "CISA_KEV"


@dataclass(frozen=True)
class KevSyncResult:
    fetched: int
    validated: int
    skipped: int
    created: int
    updated: int


def _extract_valid_entries(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    skipped = 0
    entries = payload.get("vulnerabilities", [])
    if not isinstance(entries, list):
        return records, skipped
    for entry in entries:
        try:
            records.append(normalize_kev_entry(entry))
        except KevValidationError:
            skipped += 1
    return records, skipped


def synchronize_kev(db: Session) -> KevSyncResult:
    """Fetch the full CISA KEV catalogue, validate every entry, and upsert it."""
    payload = fetch_kev_catalog()
    records, skipped = _extract_valid_entries(payload)
    created = 0
    updated = 0
    now = datetime.now(timezone.utc)

    try:
        for record in records:
            entry = db.get(KevEntry, record["cve_id"])
            if entry is None:
                db.add(KevEntry(**record, synced_at=now))
                created += 1
            else:
                for field, value in record.items():
                    setattr(entry, field, value)
                entry.synced_at = now
                updated += 1

        state = db.get(SyncState, KEV_SOURCE)
        if state is None:
            state = SyncState(source=KEV_SOURCE)
            db.add(state)
        state.last_attempted_sync = now
        state.last_successful_sync = now
        state.updated_records = created + updated
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("CISA KEV synchronization database transaction failed")
        raise

    return KevSyncResult(
        fetched=len(payload.get("vulnerabilities", [])),
        validated=len(records),
        skipped=skipped,
        created=created,
        updated=updated,
    )
