"""Client and normalizer for MITRE's official CWE REST API.

Free, no key. One weakness per request:
GET https://cwe-api.mitre.org/api/v1/cwe/weakness/{numeric id}
returns {"Weaknesses": [ {ID, Name, Description, CommonConsequences,
PotentialMitigations, RelatedWeaknesses, ...} ]}; an unknown ID is a 404.

This is the evidence a fault tree is grounded in (services/fault_tree_service.py):
the tree may only elaborate on what MITRE's own record says about the weakness.
Everything is size-bounded and validated here so an oversized or malformed
record can never balloon an LLM prompt or reach the database unchecked - the
same "validate external input" rule as fetch_cves.py and fetch_kev.py.
"""

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
import requests


CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness"
REQUEST_TIMEOUT_SECONDS = 10
_CWE_ID_PATTERN = re.compile(r"^CWE-(\d{1,5})$")

MAX_DESCRIPTION_CHARS = 1_200
MAX_CONSEQUENCES = 6
MAX_MITIGATIONS = 6
MAX_ITEM_CHARS = 300


class CweRequestError(RuntimeError):
    """Raised when the MITRE CWE API cannot be queried successfully."""


class CweNotFoundError(CweRequestError):
    """Raised when MITRE has no weakness with the requested ID."""


class CweRecordSchema(BaseModel):
    """The bounded, validated subset of a MITRE weakness record that we use."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    cwe_id: str = Field(pattern=r"^CWE-\d{1,5}$")
    name: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=MAX_DESCRIPTION_CHARS)
    consequences: list[str] = Field(default_factory=list, max_length=MAX_CONSEQUENCES)
    mitigations: list[str] = Field(default_factory=list, max_length=MAX_MITIGATIONS)


def fetch_cwe_record(cwe_id: str) -> CweRecordSchema:
    """Fetch and normalize one weakness. ``cwe_id`` is the "CWE-79" form."""
    match = _CWE_ID_PATTERN.fullmatch(cwe_id)
    if match is None:
        raise ValueError("cwe_id must look like CWE-79")
    number = str(int(match.group(1)))  # MITRE's path takes the bare number

    try:
        response = requests.get(f"{CWE_API_URL}/{number}", timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 404:
            raise CweNotFoundError(f"{cwe_id} was not found in the MITRE CWE catalogue.")
        response.raise_for_status()
        payload: Any = response.json()
    except CweNotFoundError:
        raise
    except requests.RequestException as exc:
        raise CweRequestError("Unable to retrieve the CWE record from MITRE.") from exc
    except ValueError as exc:
        raise CweRequestError("The MITRE CWE API returned invalid JSON.") from exc

    return _normalize(cwe_id, payload)


def _clip(value: Any, limit: int) -> str:
    text = " ".join(str(value).split()) if isinstance(value, (str, int, float)) else ""
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _normalize(cwe_id: str, payload: Any) -> CweRecordSchema:
    weaknesses = payload.get("Weaknesses") if isinstance(payload, dict) else None
    if not isinstance(weaknesses, list) or not weaknesses or not isinstance(weaknesses[0], dict):
        raise CweRequestError("The MITRE CWE API returned an unexpected response shape.")
    weakness = weaknesses[0]

    consequences: list[str] = []
    for item in weakness.get("CommonConsequences") or []:
        if not isinstance(item, dict):
            continue
        impacts = ", ".join(str(i) for i in item.get("Impact") or [] if isinstance(i, str))
        scopes = ", ".join(str(s) for s in item.get("Scope") or [] if isinstance(s, str))
        note = _clip(item.get("Note", ""), MAX_ITEM_CHARS)
        parts = [part for part in (f"Impact: {impacts}" if impacts else "", f"Scope: {scopes}" if scopes else "", note) if part]
        if parts:
            consequences.append(_clip("; ".join(parts), MAX_ITEM_CHARS))
        if len(consequences) == MAX_CONSEQUENCES:
            break

    mitigations: list[str] = []
    for item in weakness.get("PotentialMitigations") or []:
        if not isinstance(item, dict):
            continue
        strategy = _clip(item.get("Strategy", ""), 80)
        description = _clip(item.get("Description", ""), MAX_ITEM_CHARS)
        if description:
            mitigations.append(f"{strategy}: {description}" if strategy else description)
        if len(mitigations) == MAX_MITIGATIONS:
            break

    try:
        return CweRecordSchema(
            cwe_id=cwe_id,
            name=_clip(weakness.get("Name", ""), 300),
            description=_clip(weakness.get("Description", ""), MAX_DESCRIPTION_CHARS),
            consequences=consequences,
            mitigations=mitigations,
        )
    except ValidationError as exc:
        raise CweRequestError("The MITRE CWE record failed validation.") from exc
