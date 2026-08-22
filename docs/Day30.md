# AI-Based Threat Intelligence Assistant
# Day 30 – Testing, Evaluation & Results

**Date:** 14 August 2026

---

# Objective

Close out the 30-day build with a full functional test pass, a real measured evaluation of the pipeline against live NVD data (not fabricated numbers — the brief is explicit that actual measured results are academically stronger), and a final, honest statement of the system's architecture and limitations.

---

# Functional Testing

| Area | Result |
|---|---|
| NVD ingestion (fetch → normalize → validate → upsert) | ✓ Verified live and via `test_ingestion.py` |
| Database storage (PostgreSQL/SQLite, SQLAlchemy) | ✓ Verified live and via `test_api.py` |
| CVE search/filter/pagination (`GET /cves`) | ✓ Verified live and via `test_api.py` |
| AI-assisted analysis (evidence-grounded, rule-based) | ✓ Verified via `test_services.py` and the eval run below |
| MITRE ATT&CK inference | ✓ Verified via `test_services.py` and the eval run below |
| Mitigation recommendations | ✓ Verified via `test_services.py` and the eval run below |
| Combined intelligence endpoint (`/intelligence/{cve_id}`) | ✓ Verified live and via `test_api.py` (this is the regression test for the Day 21 bug fix) |
| Error handling (404, 422, 429, 502, 500) | ✓ Verified via `test_api.py` |
| Auth (`X-API-Key`), rate limiting, security headers | ✓ Verified via `test_api.py` |
| Prompt-injection-safe template (unused seam) | ✓ Verified via `test_prompts.py` |

**Automated test suite: 36/36 passing** (`python -m unittest discover -s backend/tests`) across `test_api.py`, `test_ingestion.py`, `test_services.py`, `test_prompts.py`, `test_schemas.py`, `test_fetch_cves.py`. `pip-audit` against `backend/requirements.txt`: no known dependency vulnerabilities.

---

# Evaluation: A Real Batch of 100 Live NVD CVEs

Rather than a small hand-picked or synthetic sample, this evaluation ran the entire pipeline — ingestion through to combined intelligence generation — against **100 real, currently-published NVD CVE records**, fetched live during this session, in an isolated local database (not the project's real deployment database — see the note at the end of this document).

## 1. Data Accuracy (Ingestion)

| Metric | Result |
|---|---|
| CVEs fetched from NVD | 100 |
| Passed Pydantic validation | 100/100 (100%) |
| Rejected/skipped as malformed | 0 |
| Successfully stored (created) | 100/100 (100%) |
| CVEs with a usable CVSS score | 83/100 (83%) |
| CVEs with a CWE classification | 86/100 (86%) |

Severity distribution across the batch: **CRITICAL 18, HIGH 34, MEDIUM 28, LOW 3, UNSCORED 17**. The 17% "unscored" figure is expected and correctly handled, not a bug — it reflects real NVD records still awaiting CVSS enrichment at time of publication (Day 11's "NVD fields can be missing" principle, empirically confirmed at scale here).

## 2. Pipeline Reliability

| Metric | Result |
|---|---|
| CVEs analyzed without an error | **100/100 (100%)** |
| CVEs receiving a complete analysis (summary, impact, risk, confidence, evidence) | 100/100 (100%) |
| CVEs receiving non-empty mitigation recommendations | 100/100 (100%) |

Zero failures across a full real batch is the direct, measurable payoff of the Day 21 bug fix and the Day 29 regression test — this is exactly the scenario (many CVEs, including ones with sparse or missing enrichment fields) that would have surfaced the stale-relationship-cache bug again if it had regressed.

## 3. AI Analysis Quality

Because this project's analysis engine is deterministic and evidence-grounded rather than an LLM (Day 17's design decision), "hallucination rate" is a different — and stronger — question than for a generative system: **every one of the 100 generated analyses is grounded 100% in stored fields by construction**, because the engine physically cannot produce a claim it didn't build from `description`, `cvss_score`, `severity`, or `cwe_id`. There is no sampled "did it hallucinate" check to run, because the failure mode doesn't exist in this architecture — this is the tradeoff described honestly on Day 17 and 20.

| Metric | Result |
|---|---|
| Average confidence score | 0.86 |
| Confidence range | 0.65 – 0.90 |
| Correlation | Every CVE below the 0.90 ceiling was one with a missing CVSS/severity field, exactly matching the Day 18 design (`confidence = 0.9 if cvss+severity present else 0.65`) |

## 4. ATT&CK Mapping Quality

| Metric | Result |
|---|---|
| CVEs receiving at least one inferred ATT&CK mapping | 6/100 (6%) |
| Technique frequency | T1059 (Command and Scripting Interpreter): 4 · T1203 (Exploitation for Client Execution): 1 · T1190 (Exploit Public-Facing Application): 1 |
| False/unsupported mappings observed | 0 (every mapping's `rationale` cites the exact matched signal phrase, spot-checked manually against its CVE description) |

A 6% mapping rate looks low next to a system that tries to map *every* CVE to *some* technique — that comparison is the point. Given the Day 22–24 design goal ("say nothing rather than guess"), a low, high-precision mapping rate is the correct, intended outcome for a five-technique, signal-based catalogue, not a shortfall. Every single one of the 6 mappings produced is directly traceable to a specific phrase in its CVE's description.

## 5. Mitigation Quality

100/100 CVEs received complete, non-empty mitigation guidance (`immediate_action`, `short_term`, `long_term`, and a `recommendations` list), including all 94 CVEs that received **zero** ATT&CK mapping — directly confirming the Day 26 design goal that mitigation guidance must remain genuinely useful even without technique-specific context, not just in the unit-tested edge case but across a real, unfiltered batch.

---

# Final Evaluation Framework Summary

| Area | Question Asked | Result |
|---|---|---|
| Data accuracy | Are CVE ID, CVSS, CWE, description retrieved correctly? | 100% ingestion success; fields correctly present/absent per real NVD data |
| Pipeline reliability | Does the full pipeline complete without error at scale? | 100/100, zero errors |
| AI quality | Is every claim grounded in evidence? | 100% by construction (deterministic, rule-based engine) |
| ATT&CK mapping | Are mappings relevant and evidence-cited when produced? | 6% coverage, 0 unsupported mappings observed |
| Mitigation quality | Are recommendations always present and actionable? | 100/100, including CVEs with no ATT&CK context |

---

# Final Architecture

```
                         ┌─────────────┐
                         │   NVD API   │
                         └──────┬──────┘
                                │
                                ▼
                    Ingestion Service (Day 13, 16)
                                │
                                ▼
                     Normalize / Validate (Day 11, 12)
                                │
                                ▼
                    ┌────────────────────┐
                    │ PostgreSQL/SQLite  │
                    └─────────┬──────────┘
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                 ▼
       AI Analysis      ATT&CK Inference   Mitigation Engine
       (Day 17-18, 20)    (Day 22-24)        (Day 25-26)
             │                │                 │
             └────────────────┼─────────────────┘
                              ▼
                Intelligence Service (Day 21, 27)
                              │
                              ▼
                         ┌──────────┐
                         │ FastAPI  │  (Day 14-15, 29 security)
                         └────┬─────┘
                              │
                              ▼
                     Dashboard (Day 28)
```

---

# Known Limitations (Stated Honestly)

- **ATT&CK catalogue is intentionally narrow** (5 techniques) — high precision, low coverage. Extending it requires the same signal-based discipline established Day 22–24, not a broad keyword expansion.
- **AI analysis is deterministic, not a live LLM** — a design decision (Day 17), with a documented, tested seam (`prompts.py`) ready for a properly safeguarded LLM integration.
- **Rate limiting is per-process, in-memory** — fine for this MVP's single-process deployment; needs shared storage to scale horizontally.
- **The dashboard has no way to supply `X-API-Key`** if a deployment enables `API_KEY` (Day 28/29 finding).
- **`ALLOWED_HOSTS` defaults to `"*"`** — should be set explicitly for any real deployment (Day 29 finding).
- **A system-level `DATABASE_URL` environment variable was discovered pointing at a live Neon Postgres instance** during this session's testing — moved into `backend/.env` this session (gitignored) for a single, documented, discoverable configuration source; the redundant system-level variable should be removed by the project owner (see `backend/.env`'s header comment for exact steps). This evaluation's 100-CVE batch deliberately ran against an isolated local database, not that real instance, to avoid writing more test data into it without the owner's awareness — that write happened once, earlier in this session, before the discovery, and was additive only (~25 real CVEs, non-destructive).

---

# Reflection

Thirty days ago this started as "can Python talk to PostgreSQL." It ends as a system that ingests real vulnerability data, stores it durably, generates evidence-grounded advisory analysis, infers MITRE ATT&CK context conservatively and honestly, recommends mitigations, and exposes all of it through a tested, rate-limited, authenticated API and a working dashboard — and, just as importantly, one that says "I don't know" (0.65 confidence, an empty ATT&CK mapping list) exactly as often as it should, rather than manufacturing false certainty. That restraint — visible in the 6% mapping rate and the explicit "not officially confirmed" language on every inference — is the actual thesis of a "software security"-focused CTI project: usefulness without overclaiming.

---

# 🎯 End-of-Day Challenge — With Answers

**1. Why is a 100% "no hallucination" rate a weaker claim for this project than it would be for an LLM-based system?**
✅ Because this project's analysis engine is deterministic and evidence-grounded by construction — it cannot produce an ungrounded claim, so there's no sampling/verification step needed to check for hallucination, unlike an LLM-based system where grounding must be actively verified against every generated response.

**2. Why is a 6% ATT&CK mapping rate presented as a success rather than a shortcoming?**
✅ Because the design goal (Day 22–24) was precision over coverage — every one of the 6 mappings is traceable to a specific, concrete signal in its CVE's description, and the alternative (mapping every CVE to some plausible-sounding technique) would trade that precision for false confidence.

**3. What was the single most valuable outcome of running the pipeline against 100 real CVEs instead of only unit tests?**
✅ Confirming 0 errors across a real, unfiltered batch — including CVEs with missing CVSS/CWE data — as direct empirical evidence that the Day 21 bug fix holds and that the "handle missing fields gracefully" principle from Day 11 actually works at the scale and variability of real data, not just in hand-picked test cases.

---

# 🎤 Interview Questions

**Q1. If you were asked to improve this system's ATT&CK mapping coverage without sacrificing precision, what would you do?**
Expand the curated catalogue (Day 23) technique by technique, each with its own specific, tested signal list — never broaden an existing technique's signals to generic single words, since that's exactly the tradeoff the current design deliberately avoided. Alternatively, integrate a real, MITRE/CAPEC-sourced official-mapping dataset (the `mapping_type: "official"` field already supports this without a schema change).

**Q2. How would this evaluation change if the AI analysis engine were replaced with a real LLM?**
The "AI quality" section would need a fundamentally different methodology: sampling generated responses and checking each claim against the source CVE record for grounding, tracking a genuine hallucination rate, and validating every response against `IntelligenceAnalysisSchema` (Day 20) before counting it as successful — none of which is necessary today specifically because the current engine cannot generate an ungrounded claim.

---

# ⚡ 5-Minute Revision

- 36/36 automated tests passing; 0 known dependency vulnerabilities.
- 100/100 real NVD CVEs ingested and analyzed without error.
- 83% had CVSS, 86% had CWE — real-world data completeness, handled correctly either way.
- 6% ATT&CK mapping rate — a precision choice, not a shortfall; 0 unsupported mappings.
- 100% of CVEs received non-empty mitigation guidance, with or without ATT&CK context.
- The project's honesty about what it doesn't know is as much a result as what it does know.

---

# Final Note on This Evaluation's Methodology

This evaluation deliberately ran against a temporary, isolated local database rather than the project's real configured database (a live Neon PostgreSQL instance discovered mid-session — see "Known Limitations" above), so that generating evaluation statistics wouldn't itself become another undisclosed write to a real, possibly-relied-upon data store. The same code paths were exercised either way; only the destination database differed.
