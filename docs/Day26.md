# AI-Based Threat Intelligence Assistant
# Day 26 – AI-Based Mitigation Recommendations

**Date:** 10 August 2026

---

# Objective

Implement `recommend_mitigations()` in [backend/services/mitigation_service.py](../backend/services/mitigation_service.py): combine a CVE's severity with its inferred ATT&CK technique(s) (Day 24) and the technique-level knowledge base (Day 25) into one structured, evidence-linked recommendation.

---

# Topics Studied

## Severity Drives Urgency

```python
def recommend_mitigations(vulnerability: VulnerabilitySchema, technique_ids: list[str]) -> MitigationResult:
    high_priority = vulnerability.severity in {"CRITICAL", "HIGH"}
    immediate = (
        "Prioritise affected-asset identification and apply the vendor-supplied security update or workaround under change control."
        if high_priority
        else "Identify affected assets and review the vendor-supplied security update or workaround."
    )
```

The wording difference is deliberate: `"Prioritise... under change control"` for CRITICAL/HIGH conveys urgency without recommending anyone skip change management even under pressure — a subtle but important operational-security point (an unreviewed emergency patch can itself cause an outage).

## Technique Context Adds Specifics

```python
recommendations = [
    "Confirm whether each asset runs an affected product and version before making a remediation decision.",
    "Apply tested vendor updates through the organisation's change-management process.",
    "Monitor relevant logs for anomalous activity while remediation is pending.",
]
for technique_id in technique_ids:
    recommendation = MITIGATION_BY_TECHNIQUE.get(technique_id)
    if recommendation and recommendation not in recommendations:
        recommendations.append(recommendation)
```

Three baseline recommendations apply to *every* vulnerability, regardless of technique mapping — even a CVE with zero inferred ATT&CK signals (Day 24 established this happens deliberately) still gets genuinely actionable guidance. Technique-specific advice is *added* on top when available, not required for the response to be useful.

## No Duplicate Recommendations

```python
if recommendation and recommendation not in recommendations:
    recommendations.append(recommendation)
```

If a CVE maps to two techniques that happen to share the same underlying mitigation text, it's added once — a small but real detail that keeps the recommendation list clean when a CVE maps to multiple related techniques.

## Unknown Technique IDs Are Ignored, Not Fatal

```python
recommendation = MITIGATION_BY_TECHNIQUE.get(technique_id)
if recommendation and ...
```

`.get()` (Day 11's pattern, applied here) means a technique ID with no corresponding entry in `MITIGATION_BY_TECHNIQUE` simply contributes nothing, rather than raising a `KeyError` and breaking the entire recommendation for that CVE.

## The `MitigationResult` Contract

```python
@dataclass(frozen=True)
class MitigationResult:
    immediate_action: str
    short_term: str
    long_term: str
    recommendations: list[str]
    source: str = "evidence-based-rules-v1"
```

Same discipline as `AnalysisResult` (Day 18): a typed, complete contract with a recorded `source` for provenance, persisted via `MitigationRecommendation` (Day 21's upsert pattern applied to a third record type alongside analysis and ATT&CK mappings).

---

# Practical Activities / Testing Performed

Added `backend/tests/test_services.py::RecommendMitigationsTests`:

- `test_high_severity_gets_an_urgent_immediate_action` / `test_low_severity_gets_a_measured_immediate_action` — confirm the severity-driven wording branch works both ways.
- `test_technique_specific_recommendation_is_appended_without_duplicating` — passes `["T1190", "T1190"]` and confirms the T1190-specific recommendation appears exactly once.
- `test_unknown_technique_id_is_ignored_rather_than_crashing` — passes a nonexistent `"T9999"` and confirms the result still has exactly the three baseline recommendations, no error.

All four pass. Also verified live: a CRITICAL CVE with no ATT&CK mapping (the XSS example from Day 24) still returned a complete, sensible `MitigationResult` with only the three baseline recommendations — confirming the "always useful, even with zero technique context" property holds in practice, not just in the unit test.

---

# Key Learnings

- Severity and technique context are genuinely independent signals that both need to shape the final recommendation — one doesn't substitute for the other.
- Even urgent guidance should reinforce process discipline ("under change control"), not just speed.
- `.get()` plus a duplicate check turns "missing or repeated technique data" into a non-event instead of a bug.
- A recommendation engine that degrades gracefully to solid generic advice (rather than failing or going empty) when specific context is missing is more useful in practice.

---

# Security Considerations

The three baseline recommendations themselves encode sound security practice independent of any specific CVE: verify applicability before acting (avoid wasted or misdirected effort), use change management (avoid self-inflicted outages from unreviewed emergency changes), and monitor while remediation is pending (detect exploitation attempts during the exposure window). Embedding these as always-present defaults means every CVE this system processes gets baseline-sound advice even in the worst case of zero additional context.

---

# Reflection

This is the day the three earlier layers (severity from NVD, technique inference, technique-level knowledge base) actually combine into the artifact a human is most likely to act on directly. Keeping the output honest — general where it has to be, specific only where the technique mapping actually earns it — was more important here than in almost any other part of the pipeline.

---

# Next Steps

- Assemble analysis, ATT&CK mappings, and mitigations into the single combined intelligence view and endpoint (Day 27) — already implemented via `intelligence_service.build_intelligence()`; verify and document it end-to-end.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why does even the CRITICAL-severity `immediate_action` still mention change control?**
✅ Because an unreviewed emergency change can itself cause an outage; urgency should increase the priority of getting the fix through change management quickly, not the temptation to skip it.

**2. Why are the three baseline recommendations always present, regardless of ATT&CK mapping?**
✅ Because a CVE can have zero inferred techniques (a deliberate, correct outcome from Day 24) and still needs genuinely actionable guidance — the baseline recommendations don't depend on technique context to be useful.

**3. What does `MITIGATION_BY_TECHNIQUE.get(technique_id)` protect against that `MITIGATION_BY_TECHNIQUE[technique_id]` would not?**
✅ A `KeyError` crash if a technique ID somehow has no corresponding mitigation entry — `.get()` returns `None` instead, which the surrounding `if recommendation and ...` check simply skips.

---

# 🎤 Interview Questions

**Q1. How would you evolve `recommend_mitigations()` if it needed to consider asset criticality (e.g. "this affected server is Internet-facing and holds customer data") in addition to CVE severity?**
Add asset-context as an explicit input parameter (rather than inferring it from the CVE alone, which has no way to know this), and let it further modulate `immediate_action`'s wording/urgency — the function signature would need to accept that context from whatever system tracks asset inventory, since a CVE record itself has no concept of "which of my assets run this."

**Q2. Why record `source="evidence-based-rules-v1"` on `MitigationResult` the same way `AnalysisResult` records `model`?**
Consistency and provenance: if a future version introduces a different mitigation-generation approach (e.g. incorporating a live vendor-advisory feed), every stored recommendation remains traceable to exactly which method produced it, which matters both for debugging and for the Day 30 evaluation.

---

# ⚡ 5-Minute Revision

- Severity → urgency wording (immediate_action), always with change-control discipline.
- Technique mapping → additional, specific recommendations layered on top of baseline advice.
- Baseline recommendations always present — useful even with zero technique context.
- `.get()` + duplicate check → missing/repeated technique IDs are handled gracefully.
- `MitigationResult` → typed contract with recorded `source`, same discipline as `AnalysisResult`.
