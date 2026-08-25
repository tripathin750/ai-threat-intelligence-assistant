"""Client and normalization helpers for CISA's Known Exploited Vulnerabilities
(KEV) catalogue - a single JSON file, no API key, no pagination, refreshed in
full on every sync (services/kev_service.py) since CISA does not expose an
incremental "changed since" query the way the NVD API does.
"""

from typing import Any

from pydantic import ValidationError
import requests

if __package__:
    from .schemas import KevEntrySchema
else:
    from schemas import KevEntrySchema


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT_SECONDS = 30


class KevRequestError(RuntimeError):
    """Raised when the CISA KEV feed cannot be retrieved successfully."""


class KevValidationError(ValueError):
    """Raised when a normalized KEV entry is unsafe to store."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("; ".join(issues))


def fetch_kev_catalog() -> dict[str, Any]:
    """Return the full CISA KEV catalogue payload."""
    try:
        response = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise KevRequestError("Unable to retrieve the CISA KEV catalogue.") from exc
    except ValueError as exc:
        raise KevRequestError("The CISA KEV feed returned invalid JSON.") from exc


def normalize_kev_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Map one raw CISA KEV entry to this app's storage shape and validate it."""
    if not isinstance(entry, dict):
        raise KevValidationError(["entry must be an object"])

    record = {
        "cve_id": entry.get("cveID"),
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "short_description": entry.get("shortDescription"),
        "required_action": entry.get("requiredAction"),
        "due_date": entry.get("dueDate"),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "notes": entry.get("notes") or None,
    }
    try:
        return KevEntrySchema.model_validate(record).model_dump()
    except ValidationError as exc:
        raise KevValidationError([error["msg"] for error in exc.errors()]) from exc
