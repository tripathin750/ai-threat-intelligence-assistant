"""Build and persist the complete, evidence-labelled intelligence view."""

from datetime import datetime, timezone

from sqlalchemy.orm import Session, joinedload

from ..data.attack_catalog import ATTACK_CATALOG
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
from .attack_service import InferredTechnique, infer_attack_techniques
from .llm_service import generate_analysis
from .mitigation_service import recommend_mitigations


_KNOWN_TECHNIQUE_IDS = {item["technique_id"] for item in ATTACK_CATALOG}
# The LLM's own confidence field describes the analysis as a whole, not any
# one technique selection, so mapped techniques get this fixed value -
# matching the deterministic keyword matcher's fixed 0.7 in spirit, but
# slightly higher since semantic matching is more reliable than a literal
# substring search.
_LLM_TECHNIQUE_CONFIDENCE = 0.75


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
    # The LLM path (services/llm_service.py) selects techniques semantically
    # from the same catalogue, so it finds far more genuine matches than a
    # literal keyword search - use its selections when it actually ran (an
    # empty list from it means "confidently found nothing", which must NOT
    # fall back to the keyword matcher; only a from-scratch deterministic
    # run should). Anything outside the known catalogue is dropped here as
    # a defence-in-depth backstop against a hallucinated technique_id (also
    # unconditionally enforced by the FK on VulnerabilityAttackMapping).
    used_llm = analysis_result.model.startswith("gemini:")
    if used_llm:
        inferred = [
            InferredTechnique(
                technique_id=technique_id,
                confidence=_LLM_TECHNIQUE_CONFIDENCE,
                rationale=rationale,
            )
            for technique_id, rationale in analysis_result.attack_techniques
            if technique_id in _KNOWN_TECHNIQUE_IDS
        ]
    else:
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
    # Same rule as above: prefer the LLM's CVE-specific recommendations over
    # the deterministic service's fixed boilerplate, but only when the LLM
    # path actually produced them (analysis_result.mitigations is required
    # non-empty by LLMAnalysisOutputSchema whenever it did).
    recommendations = (
        analysis_result.mitigations if used_llm and analysis_result.mitigations else mitigation_result.recommendations
    )
    source = analysis_result.model if used_llm and analysis_result.mitigations else mitigation_result.source
    mitigation = vulnerability.mitigations
    if mitigation is None:
        mitigation = MitigationRecommendation(cve_id=vulnerability.cve_id)
        db.add(mitigation)
    mitigation.immediate_action = mitigation_result.immediate_action
    mitigation.short_term = mitigation_result.short_term
    mitigation.long_term = mitigation_result.long_term
    mitigation.recommendations = recommendations
    mitigation.source = source
    mitigation.generated_at = datetime.now(timezone.utc)
    db.commit()
