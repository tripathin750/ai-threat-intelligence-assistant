"""Conservative mitigation recommendations based on severity and inferred ATT&CK context."""

from dataclasses import dataclass

from ..data.attack_catalog import MITIGATION_BY_TECHNIQUE
from ..schemas import VulnerabilitySchema


@dataclass(frozen=True)
class MitigationResult:
    immediate_action: str
    short_term: str
    long_term: str
    recommendations: list[str]
    source: str = "evidence-based-rules-v1"


def recommend_mitigations(
    vulnerability: VulnerabilitySchema, technique_ids: list[str]
) -> MitigationResult:
    high_priority = vulnerability.severity in {"CRITICAL", "HIGH"}
    immediate = (
        "Prioritise affected-asset identification and apply the vendor-supplied security update or workaround under change control."
        if high_priority
        else "Identify affected assets and review the vendor-supplied security update or workaround."
    )
    recommendations = [
        "Confirm whether each asset runs an affected product and version before making a remediation decision.",
        "Apply tested vendor updates through the organisation's change-management process.",
        "Monitor relevant logs for anomalous activity while remediation is pending.",
    ]
    for technique_id in technique_ids:
        recommendation = MITIGATION_BY_TECHNIQUE.get(technique_id)
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)
    return MitigationResult(
        immediate_action=immediate,
        short_term="Apply compensating controls that reduce exposure until the approved remediation is complete.",
        long_term="Maintain an accurate asset inventory, vulnerability-management cycle, and tested patch deployment process.",
        recommendations=recommendations,
    )
