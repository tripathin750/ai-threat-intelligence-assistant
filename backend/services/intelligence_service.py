"""Build and persist the complete, evidence-labelled intelligence view."""

from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from ..models import (
    IntelligenceAnalysis,
    MitigationRecommendation,
    Vulnerability,
    VulnerabilityAttackMapping,
)
from ..schemas import (
    AttackMappingSchema,
    IntelligenceAnalysisSchema,
    IntelligenceResponseSchema,
    MitigationRecommendationSchema,
    VulnerabilitySchema,
)
from .attack_service import infer_attack_techniques
from .llm_service import generate_analysis
from .mitigation_service import recommend_mitigations


DISCLAIMER = (
    "AI-assisted analysis and ATT&CK mappings are advisory, evidence-labelled inferences. "
    "NVD and vendor advisories remain the authoritative sources."
)


def build_intelligence(
    db: Session, vulnerability: Vulnerability, refresh: bool = False
) -> IntelligenceResponseSchema:
    """Return persisted intelligence, generating it once or when explicitly refreshed."""
    if refresh or vulnerability.analysis is None or vulnerability.mitigations is None:
        _generate_intelligence(db, vulnerability)
    hydrated = (
        db.query(Vulnerability)
        # populate_existing() is required here: `vulnerability` is already in
        # the session identity map, and the `vulnerability.analysis is None`
        # check above (with expire_on_commit=False) can cache a stale None
        # onto its relationship attributes even after _generate_intelligence
        # just committed matching child rows. Without this, joinedload()
        # silently keeps the cached None instead of the freshly written row.
        .populate_existing()
        .options(
            joinedload(Vulnerability.analysis),
            joinedload(Vulnerability.mitigations),
            joinedload(Vulnerability.mappings).joinedload(VulnerabilityAttackMapping.technique),
        )
        .filter(Vulnerability.cve_id == vulnerability.cve_id)
        .one()
    )
    return IntelligenceResponseSchema(
        cve=VulnerabilitySchema.model_validate(hydrated),
        analysis=IntelligenceAnalysisSchema.model_validate(hydrated.analysis),
        attack_mappings=[
            AttackMappingSchema(
                technique=mapping.technique,
                mapping_type=mapping.mapping_type,
                confidence=mapping.confidence,
                rationale=mapping.rationale,
                created_at=mapping.created_at,
            )
            for mapping in hydrated.mappings
        ],
        mitigations=MitigationRecommendationSchema.model_validate(hydrated.mitigations),
        disclaimer=DISCLAIMER,
    )


def _generate_intelligence(db: Session, vulnerability: Vulnerability) -> None:
    normalized = VulnerabilitySchema.model_validate(vulnerability)
    analysis_result = generate_analysis(normalized)
    analysis = vulnerability.analysis
    if analysis is None:
        analysis = IntelligenceAnalysis(cve_id=vulnerability.cve_id)
        db.add(analysis)
    analysis.summary = analysis_result.summary
    analysis.impact = analysis_result.impact
    analysis.affected_component = analysis_result.affected_component
    analysis.risk = analysis_result.risk
    analysis.confidence = analysis_result.confidence
    analysis.evidence = analysis_result.evidence
    analysis.model = analysis_result.model
    analysis.generated_at = datetime.now(timezone.utc)

    db.query(VulnerabilityAttackMapping).filter(
        VulnerabilityAttackMapping.cve_id == vulnerability.cve_id
    ).delete(synchronize_session=False)
    inferred = infer_attack_techniques(normalized)
    for item in inferred:
        db.add(
            VulnerabilityAttackMapping(
                cve_id=vulnerability.cve_id,
                technique_id=item.technique_id,
                mapping_type="inferred",
                confidence=item.confidence,
                rationale=item.rationale,
            )
        )
    mitigation_result = recommend_mitigations(
        normalized, [item.technique_id for item in inferred]
    )
    mitigation = vulnerability.mitigations
    if mitigation is None:
        mitigation = MitigationRecommendation(cve_id=vulnerability.cve_id)
        db.add(mitigation)
    mitigation.immediate_action = mitigation_result.immediate_action
    mitigation.short_term = mitigation_result.short_term
    mitigation.long_term = mitigation_result.long_term
    mitigation.recommendations = mitigation_result.recommendations
    mitigation.source = mitigation_result.source
    mitigation.generated_at = datetime.now(timezone.utc)
    db.commit()
