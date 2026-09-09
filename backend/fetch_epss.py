"""Client for FIRST.org's Exploit Prediction Scoring System (EPSS) API.

EPSS estimates the probability a CVE will be exploited in the wild in the
next 30 days - the third signal, alongside NVD's CVSS severity and CISA's
KEV confirmed-exploitation flag, that real commercial Risk-Based
Vulnerability Management platforms fuse together to prioritize a queue.
Free, no API key, no rate-limit registration required.

Deliberately not persisted to a table: EPSS scores are recomputed daily by
FIRST.org for every scored CVE, so a stored value goes stale immediately.
services/triage_service.py fetches live, per batch, instead.
"""

from typing import Any

import requests


EPSS_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT_SECONDS = 20
# Matches the API's own default page size - request more than this in one
# call and it silently truncates rather than erroring, so batches are
# chunked to this size instead of trusting a single oversized request.
MAX_CVES_PER_REQUEST = 100


class EpssRequestError(RuntimeError):
    """Raised when the EPSS API cannot be queried successfully."""


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Return {cve_id: epss_score} for every ID the API has a current score for.

    A CVE EPSS has never scored (e.g. brand new, or withdrawn) is simply
    absent from the result rather than raising - that is a normal, expected
    outcome for one row of a batch, not a request failure.
    """
    unique_ids = list(
        dict.fromkeys(cve_id.strip().upper() for cve_id in cve_ids if cve_id and cve_id.strip())
    )
    scores: dict[str, float] = {}
    for start in range(0, len(unique_ids), MAX_CVES_PER_REQUEST):
        chunk = unique_ids[start : start + MAX_CVES_PER_REQUEST]
        scores.update(_fetch_chunk(chunk))
    return scores


def _fetch_chunk(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    try:
        response = requests.get(
            EPSS_URL,
            params={"cve": ",".join(cve_ids), "envelope": "false"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload: Any = response.json()
    except requests.RequestException as exc:
        raise EpssRequestError("Unable to retrieve EPSS scores.") from exc
    except ValueError as exc:
        raise EpssRequestError("The EPSS API returned invalid JSON.") from exc

    scores: dict[str, float] = {}
    if not isinstance(payload, list):
        return scores
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cve")
        if not isinstance(cve_id, str):
            continue
        try:
            scores[cve_id.upper()] = float(entry.get("epss"))
        except (TypeError, ValueError):
            continue
    return scores
