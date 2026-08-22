"""MITRE ATT&CK catalogue seeding and explicitly inferred mapping helpers."""

from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..data.attack_catalog import ATTACK_CATALOG
from ..models import AttackTechnique
from ..schemas import VulnerabilitySchema


@dataclass(frozen=True)
class InferredTechnique:
    technique_id: str
    confidence: float
    rationale: str


def seed_attack_catalog(db: Session) -> None:
    """Insert/update the small versioned catalogue without removing user data."""
    for item in ATTACK_CATALOG:
        values = {key: value for key, value in item.items() if key != "signals"}
        technique = db.get(AttackTechnique, item["technique_id"])
        if technique is None:
            db.add(AttackTechnique(**values))
        else:
            for key, value in values.items():
                setattr(technique, key, value)
    db.commit()


def infer_attack_techniques(vulnerability: VulnerabilitySchema) -> list[InferredTechnique]:
    """Return mappings only where a precise signal exists in NVD description text."""
    text = vulnerability.description.casefold()
    inferred: list[InferredTechnique] = []
    for item in ATTACK_CATALOG:
        matched_signal = next((signal for signal in item["signals"] if signal in text), None)
        if matched_signal:
            inferred.append(
                InferredTechnique(
                    technique_id=item["technique_id"],
                    confidence=0.7,
                    rationale=(
                        f"Inferred from the NVD description containing the signal “{matched_signal}”. "
                        "This is not an official MITRE ATT&CK mapping."
                    ),
                )
            )
    return inferred
