# AI-Based Threat Intelligence Assistant
# Day 20 – AI Output Validation & Hallucination Control

**Date:** 4 August 2026

---

# Objective

Formalize the validation layer that sits between *any* analysis engine — the current rule-based one, or a future LLM — and the rest of the application: `IntelligenceAnalysisSchema` in [backend/schemas.py](../backend/schemas.py). The goal is that swapping the engine behind `analyse_vulnerability()` can never bypass validation, because validation lives on the output contract, not inside the engine itself.

---

# Topics Studied

## The Output Schema

```python
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
```

`confidence` is bounded `[0, 1]` — a model or rules engine claiming 140% confidence is rejected at the schema level, not trusted. `evidence` is required and typed as a list of strings, not an optional free-text field — an analysis with no evidence array is invalid by construction, which is exactly the shape hallucination-grounding needs: every claim has to correspond to *something* in that list.

## Grounding: Every Claim Traces to Evidence

The rule-based `ai_service.py` already satisfies this by construction (Day 18) — its `evidence` list is built directly from the same fields the `summary`/`impact` sentences quote. This is the property any future LLM-based implementation must also satisfy, and the Day 19 prompt explicitly instructs the model to produce evidence citations for exactly this reason.

## Confidence as a Signal, Not Decoration

Because `confidence` is a required, bounded field rather than an afterthought, `intelligence_service.py` and the frontend can both surface it meaningfully — the dashboard shows `Confidence: {percentage}%` next to every analysis (see [frontend/app.js](../frontend/app.js)), giving a human reviewer an explicit signal for how much to trust a given record before acting on it.

## Human-in-the-Loop by Design

Two structural choices keep a human in the loop rather than letting AI output be acted on blindly:

1. **`IntelligenceResponseSchema.disclaimer`** is present on every response:
   ```python
   DISCLAIMER = (
       "AI-assisted analysis and ATT&CK mappings are advisory, evidence-labelled inferences. "
       "NVD and vendor advisories remain the authoritative sources."
   )
   ```
2. **`mapping_type: Literal["inferred", "official"]`** on every ATT&CK mapping (Day 24) makes it structurally impossible for the API to claim an inferred mapping is an official MITRE assertion — the type system itself enforces the distinction, not just a comment.

## What "Hallucination Control" Means Without a Live Model

Today, hallucination control is enforced by *construction*: the rules engine physically cannot state something not present in its input, because every output string is built from the input fields themselves. The schema-validation layer exists so that property survives even after a future engine swap — at that point, hallucination control becomes enforced by *validation* (reject any output that doesn't cite grounded evidence or exceeds a plausible confidence) rather than by the engine's internal design alone. Both are needed long-term; only the first exists today, which is an honest, current limitation worth stating plainly.

---

# Practical Activities / Testing Performed

- Confirmed `IntelligenceAnalysisSchema.model_validate(hydrated.analysis)` (in `intelligence_service.py`) is the single point every stored analysis passes through before being returned as an API response — verified via `backend/tests/test_api.py::test_full_intelligence_pipeline_end_to_end`, which asserts on the validated response shape (`analysis.summary`, `analysis.risk`, `mitigations.immediate_action`, `disclaimer`) rather than on internal ORM objects.
- Manually confirmed that constructing `IntelligenceAnalysisSchema(confidence=1.4, ...)` raises a `pydantic.ValidationError`, demonstrating the bound is enforced.

---

# Key Learnings

- Validation belongs on the *output contract*, not inside a specific engine implementation — that's what lets the engine be swapped safely later.
- A required, bounded `confidence` field and a required `evidence` list turn "trust me" into something checkable.
- `Literal["inferred", "official"]` is a stronger guarantee than a comment saying "remember this is inferred" — the type system enforces it everywhere the field is used.
- Today's hallucination control is "enforced by construction" (a rules engine that can't invent facts); a future LLM-backed engine needs "enforced by validation" as well, since construction alone won't hold once free-form generation is involved.

---

# Security Considerations

Output validation is the *last* line of defense in the trust-boundary chain that runs through this whole project: NVD input is validated (Day 11), stored input is schema-validated again (Day 12), and now generated output is schema-validated before it can reach a client. No single layer is asked to carry the whole responsibility.

---

# Reflection

It would have been easy to treat "the AI doesn't hallucinate" as a property of the rules engine and stop there. Writing it up explicitly as a *schema-level* guarantee — one that has to hold regardless of what eventually generates the content — is what makes this project's advisory-analysis claim credible rather than incidental.

---

# Next Steps

- Persist the validated analysis, ATT&CK mappings, and mitigations together as one record per CVE (Day 21).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why is `confidence: float = Field(ge=0, le=1)` a hallucination-control measure, not just input validation?**
✅ It structurally prevents an engine (rules-based or, later, model-based) from ever reporting an out-of-range certainty, which would otherwise be an easy way for a broken or manipulated generation step to mislead a downstream reader.

**2. Why is `evidence: list[str]` required rather than optional?**
✅ Requiring it forces every analysis to state what it's grounded in. An analysis engine that can't produce evidence for its claims shouldn't be able to produce an analysis at all.

**3. What's the current, honest limitation of this project's hallucination control?**
✅ It's enforced by the rules engine's construction today, not yet by validating a model's free-generated claims against evidence — that second layer becomes necessary the moment a real LLM is wired in, and the schema described here is designed to be that layer.

---

# 🎤 Interview Questions

**Q1. How would you validate that a future LLM's `evidence` citations actually correspond to real fields in the CVE record, not just plausible-sounding strings?**
Beyond schema-level type checking, add a semantic check: for each evidence string, confirm it contains or closely matches a value actually present in the stored `Vulnerability` row (e.g. the CVE ID, CVSS score, or a substring of the description) before accepting the analysis — reject or flag for review otherwise.

**Q2. Why put the `disclaimer` on the API response object itself, rather than just noting it in documentation?**
Because a disclaimer in documentation is easy for a client application or a downstream consumer to never see. Attaching it to every `IntelligenceResponseSchema` guarantees it travels with the data itself, all the way to the dashboard.

---

# ⚡ 5-Minute Revision

- Validation on the output contract, not the engine → survives an engine swap.
- Bounded `confidence`, required `evidence` → checkable claims, not "trust me."
- `Literal["inferred","official"]` → type-enforced, not comment-enforced.
- Today: hallucination control by construction. Future LLM: also needs control by validation.
- `disclaimer` travels with every response, not just in docs.
