from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import foreign, relationship

if __package__:
    from .database import Base
else:
    from database import Base


class Vulnerability(Base):
    """A normalized vulnerability record obtained from the NVD."""

    __tablename__ = "vulnerabilities"

    cve_id = Column(String(30), primary_key=True, index=True)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float)
    severity = Column(String(20), index=True)
    cwe_id = Column(String(20))
    published_date = Column(DateTime)
    last_modified = Column(DateTime)
    source = Column(String(50), nullable=False, default="NVD")

    analysis = relationship(
        "IntelligenceAnalysis", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan"
    )
    mappings = relationship(
        "VulnerabilityAttackMapping", back_populates="vulnerability", cascade="all, delete-orphan"
    )
    mitigations = relationship(
        "MitigationRecommendation", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan"
    )
    # No real foreign key: KevEntry is CISA's own independent catalogue,
    # synced separately from NVD and keyed by cve_id value alone - a CVE can
    # appear in CISA KEV before this app has ever synced its NVD record (or
    # not at all, if it predates this app's recent-window sync). viewonly
    # because kev_entries is written only by services/kev_service.py.
    kev = relationship(
        "KevEntry",
        primaryjoin="Vulnerability.cve_id == foreign(KevEntry.cve_id)",
        uselist=False,
        viewonly=True,
    )


class AttackTechnique(Base):
    """Subset of the Enterprise MITRE ATT&CK catalogue used by the MVP."""

    __tablename__ = "attack_techniques"

    technique_id = Column(String(20), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    tactics = Column(JSON, nullable=False, default=list)
    external_url = Column(String(500), nullable=False)

    mappings = relationship("VulnerabilityAttackMapping", back_populates="technique")


class IntelligenceAnalysis(Base):
    """Evidence-grounded analytical assistance; it is never an authoritative CVE source."""

    __tablename__ = "intelligence_analyses"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    summary = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    affected_component = Column(Text, nullable=False)
    risk = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    evidence = Column(JSON, nullable=False, default=list)
    model = Column(String(100), nullable=False)
    generated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    vulnerability = relationship("Vulnerability", back_populates="analysis")


class VulnerabilityAttackMapping(Base):
    """A clearly labelled inferred mapping, not an official MITRE assertion."""

    __tablename__ = "vulnerability_attack_mappings"
    __table_args__ = (UniqueConstraint("cve_id", "technique_id", name="uq_cve_technique"),)

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(20), ForeignKey("attack_techniques.technique_id"), nullable=False, index=True)
    mapping_type = Column(String(30), nullable=False, default="inferred")
    confidence = Column(Float, nullable=False)
    rationale = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    vulnerability = relationship("Vulnerability", back_populates="mappings")
    technique = relationship("AttackTechnique", back_populates="mappings")


class MitigationRecommendation(Base):
    __tablename__ = "mitigation_recommendations"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    immediate_action = Column(Text, nullable=False)
    short_term = Column(Text, nullable=False)
    long_term = Column(Text, nullable=False)
    recommendations = Column(JSON, nullable=False, default=list)
    source = Column(String(100), nullable=False, default="evidence-based-rules-v1")
    generated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    vulnerability = relationship("Vulnerability", back_populates="mitigations")


class KevEntry(Base):
    """One CISA Known Exploited Vulnerabilities (KEV) catalogue entry.

    A second authoritative source alongside NVD, tracking real-world
    exploitation independently of CVSS severity - synced in full each time
    (services/kev_service.py) since CISA's feed is a single ~1,700-entry
    JSON file with no incremental/windowed query support.
    """

    __tablename__ = "kev_entries"

    cve_id = Column(String(30), primary_key=True)
    vendor_project = Column(String(200), nullable=False)
    product = Column(String(200), nullable=False)
    vulnerability_name = Column(String(300), nullable=False)
    date_added = Column(Date, nullable=False)
    short_description = Column(Text, nullable=False)
    required_action = Column(Text, nullable=False)
    due_date = Column(Date, nullable=False)
    known_ransomware_use = Column(String(20), nullable=False)
    notes = Column(Text, nullable=True)
    synced_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class SyncState(Base):
    """Stores the last completed source synchronization for incremental NVD polling."""

    __tablename__ = "sync_state"

    source = Column(String(50), primary_key=True)
    last_successful_sync = Column(DateTime(timezone=True), nullable=True)
    last_attempted_sync = Column(DateTime(timezone=True), nullable=True)
    updated_records = Column(Integer, nullable=False, default=0)
