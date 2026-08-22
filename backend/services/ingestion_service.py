"""Transactional NVD ingestion with validation, upserts, and sync state."""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..fetch_cves import VulnerabilityValidationError, fetch_modified_cves, normalize_cve
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
