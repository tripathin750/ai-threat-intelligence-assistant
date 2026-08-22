# AI-Based Threat Intelligence Assistant
# Day 23 – MITRE ATT&CK Data Integration

**Date:** 7 August 2026

---

# Objective

Bring a curated subset of the Enterprise ATT&CK catalogue into PostgreSQL, seeded from a versioned Python data file rather than a live external API — [backend/data/attack_catalog.py](../backend/data/attack_catalog.py), the `AttackTechnique` model in [backend/models.py](../backend/models.py), and `seed_attack_catalog()` in [backend/services/attack_service.py](../backend/services/attack_service.py).

---

# Topics Studied

## Why a Curated Catalogue Instead of the Full ATT&CK Dataset

The Enterprise ATT&CK matrix has hundreds of techniques; most have no meaningful connection to a CVE-driven vulnerability workflow (many describe post-compromise behaviors — lateral movement tooling, exfiltration channels — that no CVE description alone could ever responsibly imply). This project deliberately curates five techniques directly relevant to *vulnerability exploitation specifically*:

```python
ATTACK_CATALOG = (
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", ...},
    {"technique_id": "T1203", "name": "Exploitation for Client Execution", ...},
    {"technique_id": "T1210", "name": "Exploitation of Remote Services", ...},
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", ...},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", ...},
)
```

A smaller, well-chosen catalogue directly serves the Day 22 conclusion: better to have a handful of trustworthy, explainable mappings than broad coverage built on flimsy inference.

## The `AttackTechnique` Model

```python
class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    technique_id = Column(String(20), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    tactics = Column(JSON, nullable=False, default=list)
    external_url = Column(String(500), nullable=False)
```

`technique_id` (e.g. `"T1190"`) is the primary key — ATT&CK technique IDs are globally stable identifiers, a natural key. `external_url` always points back to the canonical `attack.mitre.org` page, so anyone reading a mapping in this project can go verify it against the authoritative source directly.

## Seeding, Not Live-Fetching

```python
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
```

This is the same upsert pattern used for CVE ingestion (Day 13) and analysis records (Day 21), applied to reference data: called once at every application startup (`main.py`'s `lifespan`), it's always safe to re-run — a technique already in the database is updated in place if its description in `attack_catalog.py` changes, never duplicated.

## `signals` Stay Out of the Database

```python
values = {key: value for key, value in item.items() if key != "signals"}
```

Each catalogue entry also carries a `signals` tuple (used only by the Day 24 inference function) that is deliberately excluded from what gets persisted to `AttackTechnique` — it's an internal implementation detail of *how this project infers a mapping*, not a fact about the technique itself, so it doesn't belong in the technique reference table.

## Versioned in Code, Not a Live External Dependency

Storing the catalogue as Python data rather than fetching it from MITRE's live ATT&CK STIX feed on every startup keeps the application's core functionality independent of another external service's availability, and makes exactly what's in the catalogue reviewable in a code diff — consistent with the project's broader "external data is a trust boundary" stance (Day 11), just applied here to a reference dataset the project controls the versioning of.

---

# Practical Activities / Testing Performed

- Verified `seed_attack_catalog()` runs at every app startup (`main.py::lifespan`) and is idempotent — confirmed via `backend/tests/test_api.py::test_attack_technique_catalog_is_searchable`, which relies on the catalogue already being seeded by the time the test's `TestClient` context starts.
- Live-verified `GET /attack/techniques?q=T1190` returns the seeded technique with its `external_url` pointing to `https://attack.mitre.org/techniques/T1190/`.

---

# Key Learnings

- A small, deliberately curated catalogue can be more trustworthy than broad automatic coverage — this echoes the Day 22 conclusion directly.
- The same upsert pattern (Day 13) generalizes cleanly to reference/lookup data, not just transactional records.
- Keeping internal inference logic (`signals`) separate from the persisted, externally-facing technique record keeps the database table an honest reference to what ATT&CK actually says.
- Versioning a curated external dataset as reviewable code is a legitimate alternative to a live sync when the dataset changes rarely and correctness matters more than freshness.

---

# Security Considerations

`seed_attack_catalog()` never deletes existing `AttackTechnique` rows or unrelated application data — it only inserts or updates entries present in the current `ATTACK_CATALOG` tuple, so a bad catalogue edit can't silently wipe out mappings already generated against techniques that remain in the database (`VulnerabilityAttackMapping.technique_id` has a foreign key to `attack_techniques.technique_id`, so removing a technique from the catalogue file without a migration plan would need explicit handling — worth flagging as a known limitation rather than a currently exercised code path).

---

# Reflection

This day was mostly about restraint — choosing to bring in five techniques instead of hundreds. That restraint is what makes the Day 24 inference step honest: every technique in the catalogue was chosen specifically because a CVE description can plausibly and narrowly imply it, not because ATT&CK happens to define it.

---

# Next Steps

- Implement `infer_attack_techniques()` and the explicit `inferred`/`official` mapping type (Day 24).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why does this project curate five ATT&CK techniques instead of importing the whole Enterprise matrix?**
✅ Most ATT&CK techniques describe behaviors (lateral movement, exfiltration, etc.) that a CVE description alone cannot responsibly imply. A small, deliberately chosen catalogue keeps every mapping the system can produce explainable and narrow.

**2. Why is `technique_id` the primary key instead of an auto-incrementing integer?**
✅ ATT&CK technique IDs are globally stable, externally meaningful identifiers — using them directly as the primary key avoids an unnecessary indirection and makes foreign keys from `vulnerability_attack_mappings` immediately readable.

**3. Why exclude `signals` from what's persisted to `attack_techniques`?**
✅ `signals` describes *how this project infers* a mapping, an internal implementation detail — not a fact about the ATT&CK technique itself, so it doesn't belong in a table meant to be an honest reference record.

---

# 🎤 Interview Questions

**Q1. What would you need to change to support ATT&CK sub-techniques (e.g. T1059.001) in this schema?**
`technique_id` is already a free-form `String(20)`, which comfortably fits a dotted sub-technique ID; the catalogue and inference logic would need entries for the specific sub-techniques, and the UI/schema could optionally group them under their parent technique for display.

**Q2. What's the tradeoff of seeding from versioned code instead of syncing against MITRE's live STIX/TAXII feed?**
Versioned code is simpler, has zero external dependency at startup, and every change is code-reviewable — but it requires a person to manually update the catalogue when ATT&CK itself changes, rather than picking up updates automatically. For a small, deliberately curated subset like this one, that manual step is a reasonable and arguably desirable checkpoint.

---

# ⚡ 5-Minute Revision

- Curated, small catalogue > broad automatic coverage, for explainability.
- `technique_id` (e.g. "T1190") as primary key — a natural, stable identifier.
- Same upsert pattern as CVE ingestion, applied to reference data.
- `signals` (inference detail) excluded from the persisted technique record.
- Seeded from versioned code at every startup — no live external dependency for core functionality.
