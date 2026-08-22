# AI-Based Threat Intelligence Assistant
# Day 21 – Store AI Intelligence

**Date:** 5 August 2026

---

# Objective

Persist generated analysis in PostgreSQL/SQLite rather than regenerating it on every request: the `IntelligenceAnalysis` table in [backend/models.py](../backend/models.py), populated by `_generate_intelligence()` in [backend/services/intelligence_service.py](../backend/services/intelligence_service.py).

---

# Topics Studied

## The `IntelligenceAnalysis` Model

```python
class IntelligenceAnalysis(Base):
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
```

`cve_id` is `unique=True` — this is a one-to-one relationship (`Vulnerability.analysis`, declared `uselist=False`), enforced at the database level, not just assumed in application code: a second analysis row for the same CVE would violate the unique constraint.

## `ondelete="CASCADE"`

If a `Vulnerability` row is ever deleted, its `IntelligenceAnalysis` row is deleted automatically by the database — there is no code path that can leave an orphaned analysis pointing at a CVE that no longer exists.

## Upsert, Not Always-Insert

```python
analysis = vulnerability.analysis
if analysis is None:
    analysis = IntelligenceAnalysis(cve_id=vulnerability.cve_id)
    db.add(analysis)
analysis.summary = analysis_result.summary
analysis.impact = analysis_result.impact
...
analysis.generated_at = datetime.now(timezone.utc)
```

Exactly the same upsert pattern from Day 13's CVE ingestion, applied here to analysis records: an existing analysis is updated in place (`refresh=True` re-runs this), a missing one is created. This is what makes `POST /intelligence/{cve_id}/analyze?refresh=true` safe to call repeatedly.

## Generate Once, Read Many

```python
def build_intelligence(db, vulnerability, refresh=False):
    if refresh or vulnerability.analysis is None or vulnerability.mitigations is None:
        _generate_intelligence(db, vulnerability)
    ...
```

`GET /intelligence/{cve_id}` defaults `refresh=False` — it only generates analysis the *first* time a CVE is viewed, then reads the persisted row on every subsequent call. `POST /intelligence/{cve_id}/analyze` defaults `refresh=True` — an explicit action to regenerate. This mirrors the Day 14 principle of separating expensive work from cheap reads.

## A Real Bug Found Here, and Its Fix

While verifying this pipeline end-to-end, the very first `POST /intelligence/{cve_id}/analyze` call for a brand-new CVE returned `500 Internal Server Error`. The cause: `build_intelligence`'s existence check (`vulnerability.analysis is None`) loads and *caches* `None` onto the `vulnerability` object's relationship attribute in SQLAlchemy's session identity map. Because the session is created with `expire_on_commit=False` (`database.py`), that cached `None` survives the subsequent commit inside `_generate_intelligence`. The re-hydration query right after —

```python
hydrated = db.query(Vulnerability).options(joinedload(Vulnerability.analysis), ...).filter(...).one()
```

— returns the *same* Python object from the identity map, and by default SQLAlchemy does not overwrite an already-loaded relationship attribute just because a new query ran. The fix adds `.populate_existing()`:

```python
hydrated = (
    db.query(Vulnerability)
    .populate_existing()
    .options(joinedload(Vulnerability.analysis), joinedload(Vulnerability.mitigations), ...)
    .filter(Vulnerability.cve_id == vulnerability.cve_id)
    .one()
)
```

which forces the query to refresh already-loaded attributes from the database, picking up the just-committed `IntelligenceAnalysis` and `MitigationRecommendation` rows correctly.

---

# Practical Activities / Testing Performed

- `backend/tests/test_api.py::test_full_intelligence_pipeline_end_to_end` is a direct regression test for the bug above: it calls `POST /intelligence/{cve_id}/analyze` on a CVE with **no prior analysis** and asserts `200`, then confirms a subsequent `GET` (without `refresh`) returns the identical `generated_at` timestamp — proving the second call read the persisted row instead of silently regenerating it.
- Verified live against the running app with a real NVD-ingested CVE (`CVE-2026-77992`): first `POST /analyze` returned a fully populated response; the following `GET` returned byte-for-byte the same analysis.

---

# Key Learnings

- A one-to-one relationship should be enforced with a real unique constraint at the database layer, not just assumed by the ORM model shape.
- `ondelete="CASCADE"` prevents an entire category of orphaned-row bugs without any application code having to remember to clean up related tables.
- `expire_on_commit=False` (chosen for performance — Day 10) has a real, non-obvious cost: relationship attributes accessed *before* a commit can silently go stale afterward unless a later query explicitly asks to refresh them.
- "Generate once, read many" only works correctly if "read" genuinely reads the freshly persisted state — this bug is a good example of a caching assumption breaking exactly that guarantee.

---

# Security Considerations

Persisting AI output (rather than only ever generating it on the fly) means it must be protected the same way any other stored data is: `IntelligenceAnalysisSchema` validates it on the way out (Day 20) regardless of whether it was just generated or read from storage days later, so there's no "trusted because it's already in the database" shortcut.

---

# Reflection

This was the day the project's "combined intelligence" pipeline actually got exercised end-to-end for the first time under a fresh, previously-unseen CVE — and it surfaced a genuine SQLAlchemy identity-map subtlety that unit tests alone (which had been testing each service function in isolation) hadn't caught. It's a good illustration of why integration testing through the actual API (Day 29) matters even when every underlying piece has its own passing unit tests.

---

# Next Steps

- MITRE ATT&CK catalogue and inference (Day 22–24) — already persisted alongside analysis via the same `_generate_intelligence` flow; document it properly next.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why is `cve_id` `unique=True` on `IntelligenceAnalysis` instead of relying on application code to prevent duplicates?**
✅ A database constraint holds even if application code has a bug — it's a guarantee, not a convention. Any attempt to insert a second analysis row for the same CVE fails at the database level.

**2. What does `ondelete="CASCADE"` prevent here?**
✅ An orphaned `IntelligenceAnalysis` row referencing a `Vulnerability` that's been deleted — the database removes dependent rows automatically instead of requiring every deletion code path to remember to clean them up manually.

**3. What caused the `POST /intelligence/{cve_id}/analyze` 500 error, in one sentence?**
✅ A relationship attribute (`vulnerability.analysis`) was read and cached as `None` before the matching row was created and committed, and the session's `expire_on_commit=False` setting meant that stale `None` wasn't automatically refreshed afterward — `.populate_existing()` forces the refresh explicitly.

---

# 🎤 Interview Questions

**Q1. Why did unit tests for `ai_service.py`, `attack_service.py`, and `mitigation_service.py` individually all pass, while the combined pipeline still had a bug?**
Because each of those unit tests calls its function directly with plain Python arguments — none of them exercise a real SQLAlchemy session across an existence-check → generate → commit → re-query cycle. The bug lived specifically in that session-lifecycle interaction, which only an integration test through the actual database and API surfaces.

**Q2. What's the tradeoff of `expire_on_commit=False`?**
It avoids an extra round-trip to reload every attribute after each commit (useful when a response is built from the same objects right after committing them), but it means any relationship or column read *before* a commit can go stale relative to what's actually in the database afterward unless explicitly refreshed (`db.refresh()`, `populate_existing()`, or a fresh query with cache-busting).

---

# ⚡ 5-Minute Revision

- One-to-one relationship → `unique=True` FK, not just an ORM assumption.
- `ondelete="CASCADE"` → no orphaned rows, enforced by the database.
- Upsert analysis records the same way CVEs are upserted (Day 13).
- `refresh=False` on GET, `refresh=True` on POST /analyze → generate once, read many.
- `expire_on_commit=False` + stale relationship cache → real bug, fixed with `.populate_existing()`.
