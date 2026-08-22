"""Evidence-grounded vulnerability analysis.

This service intentionally has a deterministic baseline so the project runs
without an API key and so every statement can be traced to NVD-provided data.
It is a safe seam for adding a separately reviewed LLM provider later; raw CVE
text must always remain *data*, never instructions.
"""

from dataclasses import dataclass

from ..schemas import VulnerabilitySchema


MODEL_NAME = "evidence-based-rules-v1"


@dataclass(frozen=True)
class AnalysisResult:
    summary: str
    impact: str
    affected_component: str
    risk: str
    confidence: float
    evidence: list[str]
    model: str = MODEL_NAME


def analyse_vulnerability(vulnerability: VulnerabilitySchema) -> AnalysisResult:
    """Produce conservative analyst assistance from supplied NVD fields only."""
    description = " ".join(vulnerability.description.split())
    score_evidence = (
        f"NVD CVSS base score: {vulnerability.cvss_score:.1f} ({vulnerability.severity})."
        if vulnerability.cvss_score is not None and vulnerability.severity
        else "NVD did not provide a CVSS base score and severity in this record."
    )
    cwe_evidence = (
        f"NVD weakness classification: {vulnerability.cwe_id}."
        if vulnerability.cwe_id
        else "NVD did not provide a CWE classification in this record."
    )
    evidence = [f"NVD description: {description}", score_evidence, cwe_evidence]
    risk = vulnerability.severity or "UNKNOWN"
    confidence = 0.9 if vulnerability.cvss_score is not None and vulnerability.severity else 0.65

    return AnalysisResult(
        summary=(
            f"{vulnerability.cve_id}: NVD reports {description} "
            "This summary is based only on the stored NVD record."
        ),
        impact=(
            f"The record is rated {risk}"
            + (
                f" with a CVSS base score of {vulnerability.cvss_score:.1f}."
                if vulnerability.cvss_score is not None
                else "."
            )
            + " Confirm affected products and exploitation conditions with the vendor advisory before acting."
        ),
        affected_component="Not identified from the normalized NVD fields.",
        risk=risk,
        confidence=confidence,
        evidence=evidence,
    )
