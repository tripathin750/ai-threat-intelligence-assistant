"""Transactional NVD ingestion with validation, upserts, and sync state."""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..fetch_cves import (
    CveNotFoundError,
    NVDRequestError,
    VulnerabilityValidationError,
    fetch_cve_by_id,
    fetch_modified_cves,
    normalize_cve,
)
from ..models import SyncState, Vulnerability
from ..schemas import SyncResultSchema


logger = logging.getLogger(__name__)


def _extract_valid_records(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    skipped = 0
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return records, skipped
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            skipped += 1
            continue
        try:
            records.append(normalize_cve(item["cve"]))
        except VulnerabilityValidationError:
            skipped += 1
    return records, skipped


def synchronize_nvd(db: Session, limit: int = 100) -> SyncResultSchema:
    """Fetch changed records, validate every one, and atomically upsert them."""
    state = db.get(SyncState, "NVD")
    previous_sync = state.last_successful_sync if state else None
    payload = fetch_modified_cves(previous_sync, limit=limit)
    records, skipped = _extract_valid_records(payload)
    created = 0
    updated = 0
    now = datetime.now(timezone.utc)

    # NVD may have modified more CVEs in this window than `limit` allows
    # through - fetch_modified_cves() sorts newest-first and keeps only the
    # top `limit`, silently dropping the rest. Advancing the cursor to `now`
    # in that case would permanently skip the dropped (older-in-window)
    # records, since the next sync starts looking from `now` rather than
    # resuming this window. Only advance the cursor once nothing was
    # dropped; every write below is an upsert, so re-covering the same
    # window next time costs a little duplicate work, never lost data.
    total_in_window = payload.get("totalResults", len(payload.get("vulnerabilities", [])))
    kept = len(payload.get("vulnerabilities", []))
    truncated = total_in_window > kept

    try:
        for record in records:
            vulnerability = db.get(Vulnerability, record["cve_id"])
            if vulnerability is None:
                db.add(Vulnerability(**record))
                created += 1
            else:
                for field, value in record.items():
                    setattr(vulnerability, field, value)
                updated += 1
        if state is None:
            state = SyncState(source="NVD")
            db.add(state)
        state.last_attempted_sync = now
        if not truncated:
            state.last_successful_sync = now
        state.updated_records = created + updated
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("NVD synchronization database transaction failed")
        raise

    return SyncResultSchema(
        fetched=len(payload.get("vulnerabilities", [])),
        validated=len(records),
        skipped=skipped,
        created=created,
        updated=updated,
    )


def get_or_fetch_vulnerability(db: Session, cve_id: str) -> Vulnerability:
    """Return a CVE from the local database, fetching it from NVD directly on first use.

    synchronize_nvd() only ever covers recently *modified* CVEs - NVD caps a
    date-range search at a 120-day window, so a CVE published or last
    touched years ago is never picked up by the rolling sync, no matter how
    long it runs. fetch_cve_by_id() takes no date filter at all, so any
    single, well-formed CVE ID can still be fetched directly; this is the
    on-demand escape hatch for exactly that case (the same one
    services/triage_service.py already uses per row of a pasted batch).

    Once fetched, the CVE is stored like any other synced record, so
    /intelligence/{cve_id}, search, and future triage batches all find it
    locally afterwards without fetching it again.

    Raises fetch_cves.CveNotFoundError when NVD has no record for the ID,
    NVDRequestError when NVD cannot be reached or returns something we
    don't recognise, and VulnerabilityValidationError when NVD's own record
    fails this project's validation - never silently drops or fabricates data.
    """
    cve_id = cve_id.upper()
    vulnerability = db.get(Vulnerability, cve_id)
    if vulnerability is not None:
        return vulnerability

    payload = fetch_cve_by_id(cve_id)
    if payload is None:
        raise CveNotFoundError(f"{cve_id} was not found in the NVD database.")
    raw = next(
        (item.get("cve") for item in payload.get("vulnerabilities", []) if isinstance(item, dict)),
        None,
    )
    if not isinstance(raw, dict):
        raise NVDRequestError("NVD returned an unexpected response shape.")
    record = normalize_cve(raw)  # raises VulnerabilityValidationError on failure

    vulnerability = Vulnerability(**record)
    db.add(vulnerability)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Failed to store a directly-fetched NVD record for %s", cve_id)
        raise
    return vulnerability
