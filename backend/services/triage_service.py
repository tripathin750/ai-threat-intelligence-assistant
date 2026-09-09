"""Bulk CVE triage: turn a pasted list of CVE IDs into a ranked worklist.

A SOC analyst's actual unit of work is rarely "one CVE" - it's a scanner
export or an overnight alert queue with dozens of IDs in it. Working through
that list one CVE at a time in the single-CVE intelligence view is the exact
bottleneck this module removes: every ID gets synced (if not already local),
analysed through the existing pipeline (services/intelligence_service.py -
same LLM/rules analysis, same ATT&CK mapping, same mitigations), and ranked
by urgency so the analyst sees what needs attention first, not in whatever
order the scanner happened to list it.

Never fatal per-row: a typo'd ID, a CVE NVD has never heard of, or one LLM
hiccup must not blank out the rest of a 40-row batch the analyst is staring
at before standup.
"""

from dataclasses import dataclass, field
import logging

from sqlalchemy.orm import Session

from ..fetch_cves import NVDRequestError, VulnerabilityValidationError, fetch_cve_by_id, normalize_cve
from ..models import Vulnerability
from ..schemas import CVE_ID_PATTERN
from .intelligence_service import build_intelligence


logger = logging.getLogger(__name__)

MAX_BATCH_SIZE = 50

# Lower rank sorts first. IMMEDIATE (confirmed real-world exploitation, per
# CISA KEV) outranks even a CRITICAL CVSS score that has no confirmed
# exploitation - "is someone actually using this right now" is the sharper
# triage signal than a predicted severity number.
_URGENCY_RANK = {
    "IMMEDIATE": 0,
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "UNKNOWN": 5,
    "NOT_FOUND": 6,
}


@dataclass(frozen=True)
class TriageRow:
    cve_id: str
    found: bool
    severity: str | None = None
    cvss_score: float | None = None
    kev: bool = False
    urgency: str = "NOT_FOUND"
    top_technique: str | None = None
    immediate_action: str | None = None
    confidence: float | None = None
    summary: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class TriageBatchResult:
    rows: list[TriageRow] = field(default_factory=list)
    requested: int = 0
    not_found: int = 0


def _normalize_ids(raw_ids: list[str]) -> list[str]:
    """Upper-case, strip, and dedupe while preserving first-seen order."""
    seen: dict[str, None] = {}
    for raw in raw_ids:
        cve_id = raw.strip().upper()
        if cve_id:
            seen.setdefault(cve_id, None)
    return list(seen.keys())


def _urgency_for(severity: str | None, is_kev: bool) -> str:
    if is_kev:
        return "IMMEDIATE"
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return severity
    return "UNKNOWN"


def _fetch_and_store(db: Session, cve_id: str) -> Vulnerability | None:
    """Pull one CVE from NVD when it isn't already local. Returns None (not
    an exception) when NVD has no record for it - a normal, expected outcome
    for a mistyped or not-yet-published ID within an otherwise valid batch.
    """
    try:
        payload = fetch_cve_by_id(cve_id)
    except NVDRequestError:
        logger.warning("triage: NVD lookup failed for %s", cve_id)
        return None
    if payload is None:
        return None
    raw = next((item.get("cve") for item in payload.get("vulnerabilities", []) if isinstance(item, dict)), None)
    if not isinstance(raw, dict):
        return None
    try:
        record = normalize_cve(raw)
    except VulnerabilityValidationError:
        logger.warning("triage: NVD record for %s failed validation", cve_id)
        return None
    vulnerability = Vulnerability(**record)
    db.add(vulnerability)
    db.commit()
    return vulnerability


def triage_batch(db: Session, raw_cve_ids: list[str]) -> TriageBatchResult:
    """Sync-if-needed, analyse, and urgency-rank every CVE ID in a batch."""
    cve_ids = _normalize_ids(raw_cve_ids)[:MAX_BATCH_SIZE]
    rows: list[TriageRow] = []
    not_found = 0

    for cve_id in cve_ids:
        if not CVE_ID_PATTERN.fullmatch(cve_id):
            rows.append(TriageRow(cve_id=cve_id, found=False, note="Not a valid CVE ID."))
            not_found += 1
            continue
        try:
            vulnerability = db.get(Vulnerability, cve_id)
            if vulnerability is None:
                vulnerability = _fetch_and_store(db, cve_id)
            if vulnerability is None:
                rows.append(TriageRow(cve_id=cve_id, found=False, note="Not found in NVD."))
                not_found += 1
                continue

            intelligence = build_intelligence(db, vulnerability, refresh=False)
            top_mapping = max(intelligence.attack_mappings, key=lambda m: m.confidence, default=None)
            rows.append(
                TriageRow(
                    cve_id=cve_id,
                    found=True,
                    severity=intelligence.cve.severity,
                    cvss_score=intelligence.cve.cvss_score,
                    kev=intelligence.cve.kev is not None,
                    urgency=_urgency_for(intelligence.cve.severity, intelligence.cve.kev is not None),
                    top_technique=(
                        f"{top_mapping.technique.technique_id} — {top_mapping.technique.name}"
                        if top_mapping
                        else None
                    ),
                    immediate_action=intelligence.mitigations.immediate_action,
                    confidence=intelligence.analysis.confidence,
                    summary=intelligence.analysis.summary,
                )
            )
        except Exception:  # noqa: BLE001 - one bad row must never fail the whole batch
            logger.exception("triage: unexpected failure analysing %s", cve_id)
            rows.append(TriageRow(cve_id=cve_id, found=False, note="Analysis failed; try again."))
            not_found += 1

    rows.sort(key=lambda row: (_URGENCY_RANK.get(row.urgency, 9), -(row.cvss_score or 0)))
    return TriageBatchResult(rows=rows, requested=len(cve_ids), not_found=not_found)
