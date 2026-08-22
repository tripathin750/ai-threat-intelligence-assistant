# AI-Based Threat Intelligence Assistant
# Day 18 – Building the AI Summarization Module

**Date:** 2 August 2026

---

# Objective

Implement `analyse_vulnerability()` in [backend/services/ai_service.py](../backend/services/ai_service.py): the module that turns a stored, validated `Vulnerability` record into a structured summary, impact statement, risk rating, confidence score, and evidence list — following the Day 17 decision to keep this deterministic and evidence-grounded rather than a live LLM call.

---

# Topics Studied

## The Contract: `AnalysisResult`

```python
@dataclass(frozen=True)
class AnalysisResult:
    summary: str
    impact: str
    affected_component: str
    risk: str
    confidence: float
    evidence: list[str]
    model: str = MODEL_NAME
```

Defining this as the return type — rather than a loose dict — means every caller (`intelligence_service.py`) gets IDE/type-checker support and a guarantee that all fields are present. `model = "evidence-based-rules-v1"` is recorded on every result so the *provenance* of an analysis (which engine produced it) is always known, matching the same instinct as tagging `source="NVD"` on a `Vulnerability` row.

## Building the Summary From Only Stored Fields

```python
def analyse_vulnerability(vulnerability: VulnerabilitySchema) -> AnalysisResult:
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
```

Every sentence produced is either a direct restatement of a stored field, or an explicit statement that a field was *absent* — never a filled-in guess. This mirrors the Day 11 principle of never assuming a field exists; here it becomes "never assume a value the record doesn't actually contain."

## Confidence Reflects Data Completeness, Not Model Certainty

```python
confidence = 0.9 if vulnerability.cvss_score is not None and vulnerability.severity else 0.65
```

Because there is no model doing probabilistic inference, "confidence" here means something specific and honest: *how much of the expected NVD enrichment is actually present for this record*. A CVE missing CVSS/severity data gets a lower confidence score, which is a meaningful, auditable signal rather than an arbitrary number.

## Impact Statement Includes an Explicit Caveat

```python
impact=(
    f"The record is rated {risk}"
    + (f" with a CVSS base score of {vulnerability.cvss_score:.1f}." if vulnerability.cvss_score is not None else ".")
    + " Confirm affected products and exploitation conditions with the vendor advisory before acting."
)
```

The generated text never claims to know the affected product or exploitation conditions — `affected_component` is explicitly `"Not identified from the normalized NVD fields."` when there's no reliable source field for it, and the impact statement actively directs the reader to the vendor advisory rather than implying completeness.

---

# Practical Activities / Testing Performed

Added `backend/tests/test_services.py::AnalyseVulnerabilityTests`:

- `test_evidence_is_grounded_only_in_supplied_nvd_fields` — confirms the CVE ID, description, CVSS score, and CWE all appear verbatim in the generated evidence list.
- `test_missing_cvss_and_cwe_are_reported_as_absent_not_guessed` — confirms a record with no CVSS/CWE produces explicit "did not provide" statements and a lower confidence score, rather than `None` propagating into a broken sentence or a fabricated value.

Both pass:

```
test_evidence_is_grounded_only_in_supplied_nvd_fields ... ok
test_missing_cvss_and_cwe_are_reported_as_absent_not_guessed ... ok
```

---

# Key Learnings

- A "summarization module" doesn't require a model call — it requires a clear contract for what it outputs and a disciplined rule for how it builds that output from trusted, already-validated inputs.
- Recording `model` provenance on every generated result is a small habit that pays off the moment there's more than one possible generation engine (rule-based today, potentially LLM-based later).
- Confidence is only meaningful if it's tied to something verifiable — here, data completeness — rather than being an unexplainable number.
- Explicitly stating "the record did not provide X" is more useful and more honest than silently omitting it.

---

# Security Considerations

Because the module accepts a `VulnerabilitySchema` — already validated by Pydantic (Day 12) — rather than a raw dict, it can trust every field's type and range by the time it runs. There is no path from raw external NVD JSON into this function; it only ever sees data that has already passed extraction, normalization, and validation.

---

# Reflection

Building this without an LLM turned out to clarify, rather than limit, what a "summary" needs to contain: a restatement of what's known, an explicit acknowledgment of what isn't, and a pointer to where the human should go for the rest. That's a genuinely useful structure regardless of what eventually generates the text.

---

# Next Steps

- Document what prompt engineering for this task *would* look like if an LLM were introduced, and why raw CVE text must stay data, not instructions (Day 19).
- Formalize output validation against a Pydantic schema so the same discipline applies whether the analysis comes from rules or, later, a model (Day 20).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why is `model` recorded on every `AnalysisResult`?**
✅ So every stored analysis is traceable to the specific engine/version that produced it — essential once more than one generation method (rules, then possibly an LLM) can exist side by side.

**2. Why does `confidence` drop when CVSS/severity are missing, rather than staying fixed?**
✅ Because confidence here measures how much of the relevant NVD enrichment is actually present to reason from — a record with less data genuinely supports a less complete analysis.

**3. What would break if `analyse_vulnerability` accepted a raw dict from NVD instead of `VulnerabilitySchema`?**
✅ It would have to re-implement (or skip) all the type/range checks Pydantic already guarantees, reopening exactly the "what if a field is missing or malformed" problems Day 11–12 solved.

---

# 🎤 Interview Questions

**Q1. How would you extend this module to call a real LLM without breaking its callers?**
Keep the exact function signature (`analyse_vulnerability(vulnerability: VulnerabilitySchema) -> AnalysisResult`) and the exact `AnalysisResult` shape; swap only the internal implementation, adding schema validation of the model's JSON response before constructing the dataclass. `intelligence_service.py` and everything downstream would need zero changes.

**Q2. Why is "Not identified from the normalized NVD fields" a better answer than guessing an affected component?**
Because a plausible-sounding but wrong affected component is actively worse than no answer — a security team could waste time patching or investigating the wrong system. An honest gap is safer than a confident guess.

---

# ⚡ 5-Minute Revision

- `AnalysisResult` dataclass → typed, guaranteed-complete contract.
- Every sentence traces to a stored field, or explicitly says the field is absent.
- `model` field → provenance/auditability.
- Confidence → tied to data completeness, not vibes.
- Accepts only pre-validated `VulnerabilitySchema` input.
