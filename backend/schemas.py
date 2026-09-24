"""Pydantic schemas for validated API and service data."""

from datetime import date, datetime
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_ID_PATTERN = re.compile(r"^CWE-\d+$")
VALID_SEVERITIES = frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
# The analysis `risk` field additionally allows UNKNOWN (severity does not -
# NVD either supplies a real severity or the field is left absent/None).
VALID_RISK_LEVELS = VALID_SEVERITIES | {"UNKNOWN"}


class VulnerabilitySchema(BaseModel):
    """The safe, public representation of a vulnerability record."""

    model_config = ConfigDict(from_attributes=True, extra="forbid", str_strip_whitespace=True)

    cve_id: str = Field(pattern=CVE_ID_PATTERN.pattern)
    description: str = Field(min_length=1)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: str | None = None
    cwe_id: str | None = Field(default=None, pattern=CWE_ID_PATTERN.pattern)
    published_date: datetime | None = None
    last_modified: datetime | None = None
    source: Literal["NVD"] = "NVD"

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_SEVERITIES:
            raise ValueError("must be a recognized CVSS severity")
        return value

    @field_validator("cwe_id", mode="before")
    @classmethod
    def normalize_cwe_id(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value


class AttackTechniqueSelectionSchema(BaseModel):
    """One LLM-selected ATT&CK technique. technique_id is only pattern-
    validated here (not checked against the known catalogue) - schemas.py
    does not import the data layer, so services/intelligence_service.py is
    responsible for filtering out any technique_id the LLM invents that
    isn't in data/attack_catalog.py before it ever reaches the database
    (VulnerabilityAttackMapping.technique_id is a foreign key against it).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    rationale: str = Field(min_length=1)


class LLMAnalysisOutputSchema(BaseModel):
    """The exact JSON contract services/prompts.py's SYSTEM_PROMPT asks the
    model for. The provider's raw JSON response is validated against this
    before it ever reaches the database - the same "validate everything
    external" rule this project applies to inbound NVD records - so a
    malformed or hallucinated shape from any LLM provider is rejected here.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    summary: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    affected_component: str = Field(min_length=1)
    risk: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(min_length=1)
    # Zero or more: the model is instructed to leave this empty rather than
    # force a mapping when the catalogue has no genuine match, mirroring the
    # deterministic keyword matcher's "no signal, no mapping" rule.
    attack_techniques: list[AttackTechniqueSelectionSchema] = Field(default_factory=list)
    # At least one: unlike attack technique mappings, every analysis should
    # produce at least one concrete, CVE-specific recommendation.
    mitigations: list[str] = Field(min_length=1)

    @field_validator("risk", mode="before")
    @classmethod
    def normalize_risk(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("risk")
    @classmethod
    def validate_risk(cls, value: str) -> str:
        if value not in VALID_RISK_LEVELS:
            raise ValueError("must be a recognized risk level")
        return value


class SyncResultSchema(BaseModel):
    """A validated summary of one NVD synchronization operation."""

    fetched: int = Field(ge=0)
    validated: int = Field(ge=0)
    skipped: int = Field(ge=0)
    created: int = Field(ge=0)
    updated: int = Field(ge=0)


class KevSyncResultSchema(BaseModel):
    """A validated summary of one CISA KEV catalogue synchronization."""

    fetched: int = Field(ge=0)
    validated: int = Field(ge=0)
    skipped: int = Field(ge=0)
    created: int = Field(ge=0)
    updated: int = Field(ge=0)


class KevEntrySchema(BaseModel):
    """One CISA Known Exploited Vulnerabilities catalogue entry - a second,
    independent authoritative source (real-world exploitation) alongside NVD
    (vulnerability facts). Field names mirror CISA's own feed.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid", str_strip_whitespace=True)

    cve_id: str = Field(pattern=CVE_ID_PATTERN.pattern)
    vendor_project: str = Field(min_length=1)
    product: str = Field(min_length=1)
    vulnerability_name: str = Field(min_length=1)
    date_added: date
    short_description: str = Field(min_length=1)
    required_action: str = Field(min_length=1)
    due_date: date
    known_ransomware_use: Literal["Known", "Unknown"]
    notes: str | None = None

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value


class VulnerabilityWithKevSchema(VulnerabilitySchema):
    """VulnerabilitySchema plus CISA KEV status, for API responses only -
    never used for NVD ingestion, so kev can never leak into a normalized
    record written to the database (see fetch_cves.py's normalize_cve()).
    """

    kev: KevEntrySchema | None = None


class VulnerabilityPageSchema(BaseModel):
    """A bounded database search result; clients should never load every CVE."""

    items: list[VulnerabilityWithKevSchema]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class AttackTechniqueSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str
    description: str
    tactics: list[str]
    external_url: str


class AttackMappingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    technique: AttackTechniqueSchema
    mapping_type: Literal["inferred", "official"]
    confidence: float = Field(ge=0, le=1)
    rationale: str
    created_at: datetime


class IntelligenceAnalysisSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    summary: str
    impact: str
    affected_component: str
    risk: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]
    model: str
    generated_at: datetime


class MitigationRecommendationSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    immediate_action: str
    short_term: str
    long_term: str
    recommendations: list[str]
    source: str
    generated_at: datetime


class TriageBatchRequestSchema(BaseModel):
    """A pasted/uploaded batch of CVE IDs for services/triage_service.py.
    Loose per-item validation on purpose - a mistyped or unknown ID is a
    normal, expected row outcome (see TriageRowSchema.found), not a request
    error, so this only bounds the batch size, not each ID's exact shape.
    """

    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(min_length=1, max_length=50)


class TriageRowSchema(BaseModel):
    """One ranked row of a bulk triage result - a SOC analyst's worklist
    entry, urgency-ranked from services/triage_service.py.
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    found: bool
    severity: str | None = None
    cvss_score: float | None = None
    kev: bool = False
    urgency: Literal["IMMEDIATE", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NOT_FOUND"]
    epss_score: float | None = Field(default=None, ge=0, le=1)
    top_technique: str | None = None
    immediate_action: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    summary: str | None = None
    note: str | None = None


class TriageBatchResponseSchema(BaseModel):
    """The full ranked worklist for one bulk triage request."""

    model_config = ConfigDict(extra="forbid")

    results: list[TriageRowSchema]
    requested: int = Field(ge=0)
    not_found: int = Field(ge=0)


class ImpactSummarySchema(BaseModel):
    """Aggregate counts backing the dashboard's Cost & Time Impact panel.

    Deliberately just counts, not a pre-computed money figure - the actual
    time-per-CVE and hourly-cost assumptions are edited by the viewer in the
    frontend (frontend/app.js) and never asserted here as fact, since this
    project does not know any real organization's actual analyst cost.
    """

    model_config = ConfigDict(extra="forbid")

    total_cves: int = Field(ge=0)
    analyzed_cves: int = Field(ge=0)
    kev_matches: int = Field(ge=0)


FAULT_TREE_MAX_NODES = 30
FAULT_TREE_MAX_DEPTH = 5


class FaultTreeNodeSchema(BaseModel):
    """One node of a fault tree, referring to its children by id.

    Flat (id + child ids) rather than nested on purpose: it is the shape an
    LLM's structured-output mode handles reliably, and it lets
    FaultTreeSchema verify the structure explicitly instead of trusting
    whatever nesting a model produced.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,20}$")
    label: str = Field(min_length=1, max_length=240)
    # AND: the event occurs only if ALL children occur. OR: if ANY child
    # occurs. NONE: a basic event (leaf) - a concrete, un-decomposed cause.
    gate: Literal["AND", "OR", "NONE"]
    children: list[str] = Field(default_factory=list, max_length=12)


class FaultTreeSchema(BaseModel):
    """A structurally valid fault tree: exactly one root, a real tree (no
    cycles, no node shared between two parents, nothing unreachable), gates
    that actually combine at least two causes, and leaves that are basic
    events. Enforced here because the content may come from an LLM - a
    hallucinated cycle or orphan node must be rejected before it is stored or
    drawn, never silently rendered.
    """

    model_config = ConfigDict(extra="forbid")

    root_id: str
    nodes: list[FaultTreeNodeSchema] = Field(min_length=3, max_length=FAULT_TREE_MAX_NODES)

    @model_validator(mode="after")
    def validate_structure(self) -> "FaultTreeSchema":
        by_id: dict[str, FaultTreeNodeSchema] = {}
        for node in self.nodes:
            if node.id in by_id:
                raise ValueError(f"duplicate node id {node.id!r}")
            by_id[node.id] = node
        if self.root_id not in by_id:
            raise ValueError("root_id does not refer to a node")
        for node in self.nodes:
            if node.gate == "NONE" and node.children:
                raise ValueError(f"basic event {node.id!r} must not have children")
            if node.gate != "NONE" and len(node.children) < 2:
                raise ValueError(f"{node.gate} gate {node.id!r} needs at least two children")
            if len(set(node.children)) != len(node.children):
                raise ValueError(f"gate {node.id!r} lists the same child twice")
            for child in node.children:
                if child not in by_id:
                    raise ValueError(f"node {node.id!r} refers to unknown child {child!r}")
        if by_id[self.root_id].gate == "NONE":
            raise ValueError("the top event must be a gate, not a basic event")

        seen: set[str] = set()
        stack = [(self.root_id, 1)]
        while stack:
            node_id, depth = stack.pop()
            if node_id in seen:
                raise ValueError("a node is reachable by more than one path (cycle or shared child)")
            if depth > FAULT_TREE_MAX_DEPTH:
                raise ValueError(f"tree is deeper than {FAULT_TREE_MAX_DEPTH} levels")
            seen.add(node_id)
            stack.extend((child, depth + 1) for child in by_id[node_id].children)
        if len(seen) != len(by_id):
            raise ValueError("some nodes are not reachable from the top event")
        return self


class FaultTreeResponseSchema(BaseModel):
    """The fault tree for one CWE plus where it came from."""

    model_config = ConfigDict(extra="forbid")

    cwe_id: str = Field(pattern=r"^CWE-\d{1,5}$")
    cwe_name: str
    # "gemini:<model>" when the LLM produced it, otherwise the deterministic
    # template built from MITRE's own record (suffixed "-fallback" when an
    # LLM attempt was made and failed).
    source: str
    generated_at: datetime
    tree: FaultTreeSchema
    disclaimer: str


class IntelligenceResponseSchema(BaseModel):
    """The combined, clearly sourced intelligence view for one CVE."""

    cve: VulnerabilityWithKevSchema
    analysis: IntelligenceAnalysisSchema
    attack_mappings: list[AttackMappingSchema]
    mitigations: MitigationRecommendationSchema
    disclaimer: str
