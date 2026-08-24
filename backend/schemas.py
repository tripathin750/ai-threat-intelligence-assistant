"""Pydantic schemas for validated API and service data."""

from datetime import datetime
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class VulnerabilityPageSchema(BaseModel):
    """A bounded database search result; clients should never load every CVE."""

    items: list[VulnerabilitySchema]
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


class IntelligenceResponseSchema(BaseModel):
    """The combined, clearly sourced intelligence view for one CVE."""

    cve: VulnerabilitySchema
    analysis: IntelligenceAnalysisSchema
    attack_mappings: list[AttackMappingSchema]
    mitigations: MitigationRecommendationSchema
    disclaimer: str
