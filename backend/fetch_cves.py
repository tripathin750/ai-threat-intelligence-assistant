"""Client and normalization helpers for the NVD CVE API 2.0."""

from datetime import datetime, timedelta, timezone
import os
from typing import Any

from pydantic import ValidationError
import requests

if __package__:
    from .schemas import CWE_ID_PATTERN, VulnerabilitySchema
else:
    from schemas import CWE_ID_PATTERN, VulnerabilitySchema


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 30
RECENT_WINDOWS = (timedelta(hours=1), timedelta(hours=6), timedelta(days=1))
NVD_PAGE_SIZE = 2_000


class NVDRequestError(RuntimeError):
    """Raised when the NVD API cannot be queried successfully."""


class VulnerabilityValidationError(ValueError):
    """Raised when a normalized record is unsafe to store."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("; ".join(issues))


def fetch_latest_cves(limit: int = 5) -> dict[str, Any]:
    """Return the most recently modified CVEs from the last 24 hours.

    An NVD API key is optional. If ``NVD_API_KEY`` is configured, it is sent
    in the recommended request header. The NVD API does not provide a newest-
    first option, so results are sorted locally by their ``lastModified`` date.
    """
    if not 1 <= limit <= 2_000:
        raise ValueError("limit must be between 1 and 2000")

    headers: dict[str, str] = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    end = datetime.now(timezone.utc)
    latest_page: dict[str, Any] | None = None
    latest_vulnerabilities: list[dict[str, Any]] = []

    # Start with a small period to avoid downloading a large 24-hour page
    # during normal API calls. Expand only when there are too few CVEs.
    for lookback in RECENT_WINDOWS:
        page, vulnerabilities = _fetch_recent_window(end - lookback, end, headers)
        latest_page, latest_vulnerabilities = page, vulnerabilities
        if len(vulnerabilities) >= limit:
            break

    latest_vulnerabilities.sort(
        key=lambda item: item.get("cve", {}).get("lastModified", ""), reverse=True
    )
    return {
        **(latest_page or {}),
        "resultsPerPage": min(limit, len(latest_vulnerabilities)),
        "totalResults": len(latest_vulnerabilities),
        "vulnerabilities": latest_vulnerabilities[:limit],
    }


def fetch_modified_cves(
    modified_since: datetime | None, limit: int = 100
) -> dict[str, Any]:
    """Fetch CVEs changed since a prior successful synchronization.

    NVD limits the permitted modification-date window.  The first sync looks
    back one day; stale state is capped to 119 days, so an operator can run
    several bounded catch-up syncs rather than issuing an invalid request.
    """
    if not 1 <= limit <= 2_000:
        raise ValueError("limit must be between 1 and 2000")
    headers: dict[str, str] = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    end = datetime.now(timezone.utc)
    if modified_since is None:
        start = end - timedelta(days=1)
    else:
        if modified_since.tzinfo is None:
            modified_since = modified_since.replace(tzinfo=timezone.utc)
        # Deliberate overlap prevents a record at the previous boundary from
        # being missed when NVD timestamps are rounded differently.
        start = modified_since.astimezone(timezone.utc) - timedelta(minutes=5)
    start = max(start, end - timedelta(days=119))

    page, vulnerabilities = _fetch_recent_window(start, end, headers)
    vulnerabilities.sort(
        key=lambda item: item.get("cve", {}).get("lastModified", ""), reverse=True
    )
    return {
        **page,
        "resultsPerPage": min(limit, len(vulnerabilities)),
        "totalResults": len(vulnerabilities),
        "vulnerabilities": vulnerabilities[:limit],
    }


def _fetch_recent_window(
    start: datetime, end: datetime, headers: dict[str, str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    params: dict[str, Any] = {
        "lastModStartDate": _format_nvd_datetime(start),
        "lastModEndDate": _format_nvd_datetime(end),
        "resultsPerPage": NVD_PAGE_SIZE,
        "noRejected": "",
    }
    first_page = _request_nvd(params, headers)
    vulnerabilities = first_page.get("vulnerabilities", [])
    total_results = first_page.get("totalResults", len(vulnerabilities))

    # The API response is paginated. Fetch all records in the short time
    # window before sorting, otherwise records on a later page can be newer.
    for start_index in range(NVD_PAGE_SIZE, total_results, NVD_PAGE_SIZE):
        page = _request_nvd({**params, "startIndex": start_index}, headers)
        vulnerabilities.extend(page.get("vulnerabilities", []))
    return first_page, vulnerabilities


def _request_nvd(params: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.get(
            NVD_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise NVDRequestError("Unable to retrieve CVEs from the NVD API.") from exc
    except ValueError as exc:
        raise NVDRequestError("The NVD API returned invalid JSON.") from exc


def _format_nvd_datetime(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """Extract NVD data and validate it with the Pydantic schema."""
    if not isinstance(cve, dict):
        raise VulnerabilityValidationError(["cve must be an object"])

    score, severity = _extract_cvss(cve.get("metrics", {}))
    record = {
        "cve_id": cve.get("id"),
        "description": _extract_description(cve.get("descriptions", [])),
        "cvss_score": score,
        "severity": severity,
        "cwe_id": _extract_cwe(cve.get("weaknesses", [])),
        "published_date": _parse_nvd_datetime(cve.get("published")),
        "last_modified": _parse_nvd_datetime(cve.get("lastModified")),
        "source": "NVD",
    }
    try:
        return VulnerabilitySchema.model_validate(record).model_dump()
    except ValidationError as exc:
        raise VulnerabilityValidationError(
            [error["msg"] for error in exc.errors()]
        ) from exc


def _extract_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return "No description available."
    english = next(
        (item for item in descriptions if isinstance(item, dict) and item.get("lang") == "en"),
        None,
    )
    selected = english or next((item for item in descriptions if isinstance(item, dict)), {})
    value = selected.get("value")
    if not isinstance(value, str) or not value.strip():
        return "No description available."
    return " ".join(value.split())


def _extract_cvss(metrics: Any) -> tuple[float | None, str | None]:
    # Prefer the most recent CVSS version while retaining compatibility with
    # CVEs that only contain v3 or v2 metrics.
    if not isinstance(metrics, dict):
        return None, None
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(metric_name, [])
        if not isinstance(candidates, list) or not candidates:
            continue
        metric = next(
            (
                candidate
                for candidate in candidates
                if isinstance(candidate, dict) and candidate.get("type") == "Primary"
            ),
            next((candidate for candidate in candidates if isinstance(candidate, dict)), None),
        )
        if metric is None:
            continue
        cvss_data = metric.get("cvssData", {})
        if not isinstance(cvss_data, dict):
            cvss_data = {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        try:
            normalized_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            normalized_score = None
        normalized_severity = severity.strip().upper() if isinstance(severity, str) else None
        return normalized_score, normalized_severity
    return None, None


def _extract_cwe(weaknesses: Any) -> str | None:
    if not isinstance(weaknesses, list):
        return None
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description", [])
        if not isinstance(descriptions, list):
            continue
        english = next(
            (
                item
                for item in descriptions
                if isinstance(item, dict) and item.get("lang") == "en"
            ),
            None,
        )
        selected = english or next(
            (item for item in descriptions if isinstance(item, dict)), {}
        )
        value = selected.get("value")
        if not isinstance(value, str):
            continue
        normalized_value = value.strip().upper()
        if CWE_ID_PATTERN.fullmatch(normalized_value):
            return normalized_value
    return None


def _parse_nvd_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Older NVD records may omit the timezone even though API documentation
    # specifies UTC. Treat those values consistently as UTC.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
