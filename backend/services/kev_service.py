"""Transactional CISA KEV ingestion with validation and bulk upserts.

Unlike NVD ingestion (services/ingestion_service.py), CISA's feed has no
"changed since" query - every sync fetches and validates the full ~1,700-
entry catalogue. This must be done as a small, fixed number of bulk
statements rather than one round-trip per row: against a remote database
(Neon, not a local SQLite file), ~1,700 individual get-then-write round
trips is easily 60+ seconds of pure network latency - long enough to hit
Render's own proxy timeout and drop the connection with no response at all,
exactly what happened the first time this was deployed. SyncState
(source="CISA_KEV") is reused purely for observability (last attempt/
success, record count), not for any windowing logic.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any

from sqlalchemy import bindparam, insert, select, update
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
    """Fetch the full CISA KEV catalogue, validate every entry, and bulk-upsert it.

    Two bulk statements handle every row - one INSERT for CVEs new to the
    local table, one executemany-style UPDATE for CVEs already present -
    rather than a round trip per row, which is what made the first version
    of this function time out against a remote database.
    """
    payload = fetch_kev_catalog()
    records, skipped = _extract_valid_entries(payload)
    now = datetime.now(timezone.utc)

    try:
        existing_ids = set(db.execute(select(KevEntry.cve_id)).scalars())
        to_insert = [{**record, "synced_at": now} for record in records if record["cve_id"] not in existing_ids]
        to_update = [{**record, "synced_at": now} for record in records if record["cve_id"] in existing_ids]

        if to_insert:
            db.execute(insert(KevEntry), to_insert)
        if to_update:
            # executemany-style bulk UPDATE: one SET clause, one bind
            # parameter set per row, sent as a single batched statement
            # instead of one UPDATE per row.
            for record in to_update:
                record["_cve_id"] = record["cve_id"]
            db.execute(
                update(KevEntry).where(KevEntry.cve_id == bindparam("_cve_id")),
                to_update,
                execution_options={"synchronize_session": False},
            )

        state = db.get(SyncState, KEV_SOURCE)
        if state is None:
            state = SyncState(source=KEV_SOURCE)
            db.add(state)
        state.last_attempted_sync = now
        state.last_successful_sync = now
        state.updated_records = len(to_insert) + len(to_update)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("CISA KEV synchronization database transaction failed")
        raise

    return KevSyncResult(
        fetched=len(payload.get("vulnerabilities", [])),
        validated=len(records),
        skipped=skipped,
        created=len(to_insert),
        updated=len(to_update),
    )
