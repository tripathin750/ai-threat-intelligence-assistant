# AI-Based Threat Intelligence Assistant
# Day 27 – Build the Complete Threat Intelligence Pipeline

**Date:** 11 August 2026

---

# Objective

Bring every previous layer together behind one endpoint: `GET /intelligence/{cve_id}` and `POST /intelligence/{cve_id}/analyze` in [backend/main.py](../backend/main.py), backed by `build_intelligence()` in [backend/services/intelligence_service.py](../backend/services/intelligence_service.py). This is the feature the rest of the dissertation's system description points at.

---

# Topics Studied

## The Assembled Architecture

```
                        NVD API
                           │
                           ▼
                 Ingestion Service (Day 13, 16)
                (fetch → normalize → validate → upsert)
                           │
                           ▼
                     PostgreSQL / SQLite
                     (Vulnerability row)
                           │
              ┌────────────┼────────────┐
              ▼            ▼             ▼
        AI Analysis   ATT&CK Inference  Mitigation Engine
        (Day 17-18)     (Day 22-24)      (Day 25-26)
              │            │             │
              └────────────┼─────────────┘
                           ▼
              build_intelligence() (Day 21, 27)
              persists IntelligenceAnalysis,
              VulnerabilityAttackMapping[],
              MitigationRecommendation
                           │
                           ▼
              IntelligenceResponseSchema
              { cve, analysis, attack_mappings[],
                mitigations, disclaimer }
                           │
                           ▼
                        FastAPI
                           │
                           ▼
                  Dashboard (Day 28)
```

## One Function Orchestrates, It Doesn't Duplicate Logic

```python
def build_intelligence(db: Session, vulnerability: Vulnerability, refresh: bool = False) -> IntelligenceResponseSchema:
    if refresh or vulnerability.analysis is None or vulnerability.mitigations is None:
        _generate_intelligence(db, vulnerability)
    hydrated = (
        db.query(Vulnerability).populate_existing()
        .options(joinedload(Vulnerability.analysis), joinedload(Vulnerability.mitigations),
                  joinedload(Vulnerability.mappings).joinedload(VulnerabilityAttackMapping.technique))
        .filter(Vulnerability.cve_id == vulnerability.cve_id).one()
    )
    return IntelligenceResponseSchema(
        cve=VulnerabilitySchema.model_validate(hydrated),
        analysis=IntelligenceAnalysisSchema.model_validate(hydrated.analysis),
        attack_mappings=[...],
        mitigations=MitigationRecommendationSchema.model_validate(hydrated.mitigations),
        disclaimer=DISCLAIMER,
    )
```

`build_intelligence()` doesn't reimplement analysis, inference, or mitigation logic — it calls `analyse_vulnerability()`, `infer_attack_techniques()`, and `recommend_mitigations()` (each independently built and tested, Days 18/24/26) and assembles their results. This is the payoff of the layered architecture introduced back on Day 12: each service stays independently testable and swappable, and the orchestration layer stays thin.

## Two Endpoints, One Function, Different Defaults

```python
@app.post("/intelligence/{cve_id}/analyze", response_model=IntelligenceResponseSchema, ...)
def analyse_cve(cve_id, refresh: bool = Query(default=True), db=Depends(get_db)):
    return build_intelligence(db, _get_vulnerability_or_404(db, cve_id), refresh=refresh)

@app.get("/intelligence/{cve_id}", response_model=IntelligenceResponseSchema, ...)
def get_intelligence(cve_id, refresh: bool = Query(default=False), db=Depends(get_db)):
    return build_intelligence(db, _get_vulnerability_or_404(db, cve_id), refresh=refresh)
```

`POST .../analyze` is the explicit "(re)generate" action (`refresh=True` by default); `GET /intelligence/{cve_id}` is the cheap "read what's there, generating once if this CVE has never been analyzed" path (`refresh=False` by default). Using `POST` for the action that writes/regenerates and `GET` for the primarily-read path follows HTTP semantics correctly — a `GET` should be safe to call repeatedly without an operator worrying it will discard and regenerate existing analysis.

## Every Response Carries Its Own Provenance

`IntelligenceResponseSchema.disclaimer` and each mapping's `mapping_type` travel with *every* response — a client (the Day 28 dashboard, or any future consumer) never has to separately know or remember "oh, this endpoint's data is advisory." That property is encoded in the data itself.

---

# Practical Activities / Testing Performed

This was verified fully end-to-end against the live NVD API and a local SQLite database, not just through unit tests:

```
POST /cves/sync?limit=20
  → {"fetched":20,"validated":20,"skipped":0,"created":20,"updated":0}

GET /cves?limit=5
  → 5 real, currently-published CVEs returned, correctly filtered/paginated

POST /intelligence/CVE-2026-77992/analyze
  → 200 OK — full IntelligenceResponseSchema: analysis, attack_mappings ([] — no
    signal matched this CVE's text, a correct outcome), mitigations, disclaimer

GET /intelligence/CVE-2026-77992
  → 200 OK — identical persisted record, confirming refresh=False reads rather
    than regenerates

Synthetic technique-matching check:
  description = "...remote command injection...web application...arbitrary
  command execution."
  → attack_mappings correctly included both T1190 and T1059
```

This live run also surfaced and led to fixing the `.populate_existing()` bug documented on Day 21 — the very first `POST /intelligence/{cve_id}/analyze` call against a brand-new CVE failed with a `500` before the fix.

`backend/tests/test_api.py::test_full_intelligence_pipeline_end_to_end` now codifies this as a permanent regression test, run on every test suite execution rather than only manually.

---

# Key Learnings

- An orchestration layer's job is composition, not reimplementation — `build_intelligence()` is almost entirely calls to already-tested functions.
- HTTP method choice (`GET` vs `POST`) should reflect whether an operation is safe to repeat without side effects, not just "which one is more convenient."
- Provenance/disclaimer data belongs *in* the response object, not in documentation alongside it.
- Live, end-to-end verification against the real external API caught a bug that isolated unit tests of each service, individually, did not — both kinds of testing are necessary (formalized further on Day 29).

---

# Security Considerations

This endpoint is the highest-value target in the API from a "what could go wrong" standpoint — it touches the database, the NVD-sourced record, and every advisory layer at once. It sits behind the same `verify_api_key` dependency, `RateLimitMiddleware`, and `SecurityHeadersMiddleware` (Day 29) as every other route; nothing about combining multiple subsystems into one response required a new or different trust model, because each subsystem was already independently validated on its own terms.

---

# Reflection

Seeing `CVE-2026-77992` go from a raw NVD JSON blob to a fully assembled, evidence-labelled intelligence record — summary, ATT&CK context (or an honest absence of it), and mitigation guidance, all in one response — is the moment this stopped feeling like a collection of separate exercises and started feeling like the actual product described in the dissertation's problem statement.

---

# Next Steps

- Confirm the dashboard renders this combined response correctly end-to-end (Day 28, already implemented — verify and document).
- Formal security review pass and consolidated automated test suite (Day 29).
- Final evaluation and results write-up (Day 30).

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why does `build_intelligence()` call into `ai_service`, `attack_service`, and `mitigation_service` rather than containing that logic itself?**
✅ Keeping each concern in its own independently-tested module (Day 12's layered architecture) means `build_intelligence()` can stay a thin, reviewable orchestrator, and any one layer (e.g. swapping the AI engine per Day 17) can change without touching this function.

**2. Why is `POST /intelligence/{cve_id}/analyze` the right verb for regeneration, and `GET` the right verb for the default read?**
✅ `GET` should be safe to call repeatedly without changing server state unexpectedly; defaulting it to `refresh=False` (read, generate-once-if-missing) respects that. `POST` correctly signals an action with a side effect (regenerating and overwriting stored analysis).

**3. What real bug did end-to-end testing catch that unit tests of `ai_service`, `attack_service`, and `mitigation_service` individually did not?**
✅ The stale-relationship-cache bug (Day 21) — each service function worked correctly in isolation; the bug lived specifically in the session-lifecycle interaction between the existence check, the commit, and the re-hydration query, which only a real database session across a full request cycle exercises.

---

# 🎤 Interview Questions

**Q1. Walk through what happens, end to end, for a `POST /intelligence/{cve_id}/analyze` call on a CVE that's never been analyzed before.**
`verify_api_key` and `RateLimitMiddleware` run first; `_get_vulnerability_or_404` loads the CVE or returns 404; `build_intelligence` sees `vulnerability.analysis is None`, calls `_generate_intelligence`, which runs the rules-based analysis, signal-based ATT&CK inference, and severity/technique-aware mitigation generation, persists all three, and commits; the function then re-queries with `populate_existing()` to get a correctly hydrated object, and returns the assembled, schema-validated `IntelligenceResponseSchema`.

**Q2. If you needed to add a fourth advisory layer (say, exploit-availability signals from a feed like CISA KEV) to this pipeline, where would it go?**
As its own service module (`services/exploit_signal_service.py`) with its own typed result contract, called from `_generate_intelligence()` alongside the other three, persisted as its own table/relationship on `Vulnerability`, and added as a new field on `IntelligenceResponseSchema` — following exactly the same pattern the existing three layers use.

---

# ⚡ 5-Minute Revision

- `build_intelligence()` = orchestration, not reimplementation.
- `POST .../analyze` (refresh=True default) vs `GET /intelligence/{cve_id}` (refresh=False default) — verb matches HTTP semantics.
- Disclaimer and mapping_type travel inside the response data itself.
- End-to-end testing against the real pipeline caught a bug isolated unit tests couldn't.
- This endpoint is the project's core deliverable — everything before Day 27 built toward it.
