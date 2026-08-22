# AI-Based Threat Intelligence Assistant
# Day 24 – CVE → MITRE ATT&CK Mapping

**Date:** 8 August 2026

---

# Objective

Implement the CVE→ATT&CK inference itself — `infer_attack_techniques()` in [backend/services/attack_service.py](../backend/services/attack_service.py) — and persist its results with an explicit, type-enforced distinction between an inferred mapping and an official one: `VulnerabilityAttackMapping` in [backend/models.py](../backend/models.py).

---

# Topics Studied

## Signal-Based, Not Broad Keyword Matching

```python
def infer_attack_techniques(vulnerability: VulnerabilitySchema) -> list[InferredTechnique]:
    """Return mappings only where a precise signal exists in NVD description text."""
    text = vulnerability.description.casefold()
    inferred: list[InferredTechnique] = []
    for item in ATTACK_CATALOG:
        matched_signal = next((signal for signal in item["signals"] if signal in text), None)
        if matched_signal:
            inferred.append(InferredTechnique(
                technique_id=item["technique_id"],
                confidence=0.7,
                rationale=(
                    f"Inferred from the NVD description containing the signal "{matched_signal}". "
                    "This is not an official MITRE ATT&CK mapping."
                ),
            ))
    return inferred
```

Each catalogue entry (Day 23) carries a `signals` tuple of specific phrases — e.g. T1190's signals are `("public-facing", "web application", "web server", "internet-facing", "http server")`, not a single generic word like `"exploit"` that would match almost every CVE indiscriminately. This is the concrete implementation of the Day 22 conclusion: narrow and explainable over broad and noisy.

## The Rationale Is Not Optional Decoration

Every inferred mapping's `rationale` states *exactly which phrase* triggered it and explicitly states it is *not* an official mapping — in the string itself, not just in a separate field a caller might ignore. Anyone reading one mapping in isolation (in the API response or the dashboard) sees the disclaimer without needing to cross-reference anything else.

## Persisting the Distinction With a Type, Not a Comment

```python
class VulnerabilityAttackMapping(Base):
    __tablename__ = "vulnerability_attack_mappings"
    __table_args__ = (UniqueConstraint("cve_id", "technique_id", name="uq_cve_technique"),)

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(30), ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(20), ForeignKey("attack_techniques.technique_id"), nullable=False, index=True)
    mapping_type = Column(String(30), nullable=False, default="inferred")
    confidence = Column(Float, nullable=False)
    rationale = Column(Text, nullable=False)
```

and, on the API side:

```python
class AttackMappingSchema(BaseModel):
    technique: AttackTechniqueSchema
    mapping_type: Literal["inferred", "official"]
    confidence: float = Field(ge=0, le=1)
    rationale: str
```

`Literal["inferred", "official"]` means Pydantic itself rejects any response that doesn't use one of those two exact values — there is no code path, today or after a future change, that can silently produce a mapping whose type is ambiguous or missing. Today, every mapping this project generates is `"inferred"`; `"official"` exists in the type now specifically so that a future feature (importing real MITRE-curated CVE↔technique mappings, e.g. via CAPEC) has somewhere correct to go without a schema change.

## `UniqueConstraint("cve_id", "technique_id")`

Prevents the same technique from being mapped to the same CVE twice — relevant because `_generate_intelligence()` (Day 21) deletes and regenerates a CVE's mappings on every `refresh=True` call:

```python
db.query(VulnerabilityAttackMapping).filter(VulnerabilityAttackMapping.cve_id == vulnerability.cve_id).delete(synchronize_session=False)
inferred = infer_attack_techniques(normalized)
for item in inferred:
    db.add(VulnerabilityAttackMapping(cve_id=..., technique_id=item.technique_id, ...))
```

Delete-then-reinsert (rather than a more complex diff/upsert) is a deliberate simplicity choice here: mappings are cheap to regenerate and there's no history requirement for *which* mappings existed previously, unlike `Vulnerability` rows themselves.

## Fixed Confidence, Not a Tunable Score

Every inferred mapping currently gets `confidence=0.7` — a fixed, moderate value rather than a computed one, because the signal-matching approach genuinely doesn't have a principled way to distinguish "more confident" from "less confident" matches yet. A fixed, honest middle value is more defensible than a fabricated precision the method can't actually support.

---

# Practical Activities / Testing Performed

Added `backend/tests/test_services.py::InferAttackTechniquesTests`:

- `test_matches_multiple_independent_signals` — a description containing both "web application" and "command injection" correctly produces both T1190 and T1059, confirming multiple independent signals are each detected.
- `test_no_mapping_without_a_concrete_signal` — a generic "cross-site scripting" description (no configured signal for it in the current five-technique catalogue) correctly produces zero mappings rather than a forced guess.
- `test_rationale_explicitly_labels_the_mapping_as_inferred` — confirms the disclaimer text is present in the rationale itself.

Also live-verified via `POST /intelligence/{cve_id}/analyze` against a real ingested CVE containing "Unauthenticated stored XSS" — correctly produced **no** ATT&CK mapping (no configured signal matches XSS-only text in the current catalogue), demonstrating the system's willingness to say nothing rather than force a low-quality guess.

---

# Key Learnings

- Specific multi-word signals ("web application", "command injection") dramatically reduce false-positive mappings compared to single generic keywords.
- A disclaimer embedded in the data itself (the `rationale` string) survives being read in isolation, unlike a disclaimer that only exists elsewhere in a document or response.
- `Literal["inferred", "official"]` turns a policy ("never claim an inference is official") into something the type system enforces, not something a future contributor has to remember.
- Delete-and-reinsert is an acceptable, simpler alternative to upsert when the records being replaced have no independent history requirement.
- It's fine — good, even — for an inference system to produce zero results when it has no genuine basis for a claim.

---

# Security Considerations

Overclaiming a security finding (asserting a mapping with unwarranted confidence) has real operational cost: a defender who trusts a wrong "official" ATT&CK label could misdirect detection engineering effort. The `Literal` type constraint, the always-present disclaimer text, and the deliberately conservative signal list are all responses to that specific risk, not generic engineering hygiene.

---

# Reflection

The most important design decision on this day wasn't the matching logic itself — it was the decision to let the function return an empty list. A system that always finds *something* to say is, paradoxically, less trustworthy than one willing to say nothing when it genuinely doesn't know.

---

# Next Steps

- Build out the mitigation-recommendation knowledge base these mapped techniques feed into (Day 25–26).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why does `infer_attack_techniques` use multi-word signals instead of single keywords?**
✅ Single generic keywords (e.g. "exploit") would match nearly every CVE description, producing noisy, low-value mappings. Specific phrases narrow matches to descriptions that genuinely support the inference.

**2. Why is the disclaimer embedded in the `rationale` string, not just a separate field?**
✅ So the caveat travels with the mapping even if it's read or displayed in isolation, rather than depending on a caller to also check and surface a separate field.

**3. What does `Literal["inferred", "official"]` guarantee that a free-form string field wouldn't?**
✅ It's impossible for any code path to produce or accept a mapping whose type isn't exactly one of those two values — Pydantic rejects anything else at validation time, rather than relying on convention.

---

# 🎤 Interview Questions

**Q1. Why delete and regenerate ATT&CK mappings on every `refresh=True` call instead of diffing and updating them?**
Mappings have no independent history requirement — unlike a CVE record, there's no need to know what a mapping "used to be." Given that, delete-then-reinsert is simpler and just as correct as a diff-based upsert, and the `UniqueConstraint` still prevents duplicates within one generation pass.

**Q2. How would you extend this system to eventually store real, MITRE/CAPEC-sourced official mappings alongside the inferred ones?**
Add an ingestion path that populates `VulnerabilityAttackMapping` rows with `mapping_type="official"` from a curated source, keyed by the same `(cve_id, technique_id)` uniqueness — the schema and `Literal` type already support this without any changes; only a new data source integration would be needed.

---

# ⚡ 5-Minute Revision

- Specific multi-word signals, not generic keywords → fewer false positives.
- Rationale states the exact matched signal and the "not official" disclaimer, inline.
- `mapping_type: Literal["inferred", "official"]` → type-enforced, not just documented.
- `UniqueConstraint(cve_id, technique_id)` → no duplicate mappings.
- Fixed, honest confidence (0.7) over a fabricated precise score.
- Zero mappings is a valid, good outcome when there's no real signal.
