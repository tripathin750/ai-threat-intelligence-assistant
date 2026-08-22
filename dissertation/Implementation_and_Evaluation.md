# AI-Based Threat Intelligence Assistant
# Implementation and Evaluation

*Consolidated from the Day 1–30 development log in [../docs/](../docs/). This document synthesizes that log into a single, reviewable narrative suitable for direct use as a dissertation chapter; it should be read alongside the architecture and ER diagrams in [../diagrams/](../diagrams/).*

---

## 1. Introduction and Objective

The AI-Based Threat Intelligence Assistant is a system that ingests vulnerability data from the National Vulnerability Database (NVD), stores it persistently, and layers advisory analysis on top: an evidence-grounded summary, an inferred MITRE ATT&CK technique mapping, and severity/technique-aware mitigation guidance. The project's central design constraint, established early and enforced throughout, is a strict separation between **fact and inference**: NVD-reported fields (CVE ID, description, CVSS score, CWE) are treated as authoritative; everything the system itself generates is explicitly labelled advisory and evidence-cited, never presented as an independent source of truth.

This document covers the system's implementation (Sections 2–7), its security posture (Section 8), and its evaluation against real, live data (Section 9) — the latter using actual measured results rather than illustrative figures, in line with the project's own evidence-first principle.

---

## 2. System Architecture

```
NVD API → Ingestion Service → PostgreSQL/SQLite → { AI Analysis, ATT&CK Inference, Mitigation Engine } → Intelligence Service → FastAPI → Dashboard
```

See [../diagrams/architecture.md](../diagrams/architecture.md) for the full component diagram and [../diagrams/er-diagram.md](../diagrams/er-diagram.md) for the database schema. The system is deliberately layered (API / service / data), a decision made explicitly on Day 12 specifically to keep each concern — HTTP handling, business logic, persistence — independently testable and replaceable.

---

## 3. Data Ingestion (Days 5, 11, 13, 16)

Vulnerability data enters the system exclusively through `services/ingestion_service.py::synchronize_nvd()`, which:

1. Reads the last successful synchronization timestamp from a dedicated `SyncState` table, enabling **incremental** synchronization rather than repeated full downloads (NVD's own `lastModStartDate`/`lastModEndDate` parameters are used for this).
2. Fetches changed records from the NVD CVE API 2.0, handling pagination internally.
3. **Extracts and normalizes** every record (`fetch_cves.py::normalize_cve()`) — selecting the newest available CVSS version across v2/v3.0/v3.1/v4.0, safely handling missing optional fields with `.get()` rather than direct key access, and normalizing text (whitespace, case) into a consistent internal format.
4. **Validates** every normalized record against a strict Pydantic schema (`VulnerabilitySchema`) before it is allowed anywhere near the database — malformed records are discarded and counted, never silently accepted.
5. **Upserts**: an existing CVE (by primary key `cve_id`) is updated in place; a new one is inserted. This is essential because CVE records are revised over time (a new CVSS score, an updated description), not immutable once published.
6. Commits the whole batch as a single transaction, rolling back cleanly on any database error.

This pipeline treats the NVD API as a **trust boundary**: even though NVD is a reputable source, the system never assumes a field exists, is well-typed, or is within an expected range without checking.

---

## 4. Persistence Layer (Days 10, 21)

SQLAlchemy models (`models.py`) represent six tables: `vulnerabilities` (the core record), `attack_techniques` (a curated ATT&CK catalogue), `intelligence_analyses`, `mitigation_recommendations`, `vulnerability_attack_mappings`, and `sync_state`. Every advisory table (`intelligence_analyses`, `mitigation_recommendations`) enforces a true one-to-one relationship with its parent CVE via a `UNIQUE` foreign key constraint and cascades on delete, so no advisory record can exist for a CVE that no longer does.

The application supports both PostgreSQL (via the `psycopg` driver) and SQLite (a zero-configuration default for local development and testing) through a single `DATABASE_URL` setting, with no code branching required — this is one of SQLAlchemy's core value propositions and was exercised directly during this project's own testing (Section 9).

---

## 5. Advisory Intelligence Layer (Days 17–26)

### 5.1 AI Analysis — A Deliberately Non-Generative Design

Rather than calling a live LLM, `services/ai_service.py::analyse_vulnerability()` is a **deterministic, evidence-grounded rules engine**: every sentence it produces is built directly from already-validated, stored fields (`description`, `cvss_score`, `severity`, `cwe_id`). This was a considered architectural decision (Day 17), not a placeholder — it removes an entire class of risk (hallucination, prompt injection from untrusted CVE description text) that a naive LLM integration would introduce, at the cost of not producing the kind of free-form synthesis a language model could. A fully specified, tested prompt template for a future LLM integration exists (`services/prompts.py`, Day 19) as a documented "safe seam," but is not wired into the running application.

### 5.2 MITRE ATT&CK Inference — Precision Over Coverage

`services/attack_service.py::infer_attack_techniques()` matches a CVE's description text against a small, curated catalogue of five Enterprise ATT&CK techniques (`data/attack_catalog.py`), each with a specific set of multi-word signal phrases (e.g. `"web application"`, `"command injection"`) rather than generic single-word keywords. Every inferred mapping is persisted with `mapping_type: Literal["inferred", "official"]` — a type-level guarantee that an inference can never be presented as an official MITRE assertion — and its `rationale` field states the exact matched phrase inline. The evaluation in Section 9 confirms this produces a low-coverage, high-precision result set by design.

### 5.3 Mitigation Recommendations

`services/mitigation_service.py::recommend_mitigations()` combines CVE severity (driving urgency wording) with any inferred ATT&CK techniques (adding specific, technique-scoped guidance from a curated knowledge base) into a structured recommendation with immediate/short-term/long-term horizons. Three baseline recommendations are always present, ensuring every CVE — including the majority with no ATT&CK mapping — receives genuinely actionable guidance.

### 5.4 Combined Intelligence View

`services/intelligence_service.py::build_intelligence()` orchestrates the three layers above and persists the result, generating once and serving cached results thereafter (`GET /intelligence/{cve_id}`), with an explicit regeneration path (`POST /intelligence/{cve_id}/analyze`). See [../diagrams/sequence-intelligence-request.md](../diagrams/sequence-intelligence-request.md) for the full request sequence, including a documented SQLAlchemy session-identity-map bug found and fixed during this project's live testing (Day 21).

---

## 6. API Layer (Days 14–15, 27)

FastAPI exposes the system through a REST API with database-side search/filter/pagination (`GET /cves`), single-record retrieval, ingestion triggers, the combined intelligence endpoints, and an ATT&CK catalogue browser. Every route parameter is validated by Pydantic/FastAPI before reaching application code; every exception class is mapped to a specific, appropriate HTTP status (`404`, `422`, `429`, `502`, `500`) with detailed logging server-side and only generic messages returned to the client.

---

## 7. Frontend Dashboard (Day 28)

A deliberately framework-free HTML/CSS/vanilla-JavaScript dashboard, served by the same FastAPI process at `/dashboard/`, provides search/filter/pagination and a detail panel rendering the full combined intelligence view — including an honest, explicit "no ATT&CK technique inferred" message when applicable, rather than a blank or ambiguous state. Every API-sourced value is rendered via `textContent`, never `innerHTML`, which is the dashboard's actual (and sufficient) XSS defense given that CVE description text originates from an external source.

---

## 8. Security Considerations (Day 29)

A structured review was performed against the running application, covering:

- **Injection**: all database access goes through SQLAlchemy's parameterized expression API; no raw SQL string concatenation with user input exists anywhere in the codebase.
- **Authentication**: an optional `X-API-Key` header, checked with `hmac.compare_digest()` for constant-time comparison (preventing a timing side-channel attack).
- **Rate limiting**: an in-memory, per-client sliding-window limiter, acceptable for this MVP's single-process deployment model.
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Cross-Origin-Opener-Policy` are set on every response.
- **Secrets handling**: database credentials and API keys are read from environment variables / a gitignored `.env` file, never hardcoded or logged.
- **Dependency vulnerabilities**: `pip-audit` against the full dependency set reported no known vulnerabilities.

Findings are stated plainly rather than hidden: `ALLOWED_HOSTS` defaults to `"*"` for local development convenience and should be set explicitly for any real deployment; the rate limiter would need shared storage to operate correctly across multiple processes; the AI analysis engine's groundedness is a property of its deterministic construction today, not yet of an independently verified validation layer (relevant if a future LLM integration is added).

---

## 9. Evaluation

### 9.1 Automated Testing

37 automated tests (`backend/tests/`) cover schema validation, NVD data normalization, service-level logic (analysis, ATT&CK inference, mitigation generation), ingestion/upsert/duplicate-handling behavior against a mocked NVD client, and full API integration tests (including authentication, rate limiting, security headers, and the combined intelligence pipeline) — all passing at the time of writing. `pip-audit` reports zero known dependency vulnerabilities.

### 9.2 Real-Data Evaluation

The full pipeline was run end-to-end against **100 real, live NVD CVE records**, fetched during this project's development:

| Metric | Result |
|---|---|
| Ingestion success rate | 100/100 (100%) |
| CVEs with a usable CVSS score | 83/100 (83%) |
| CVEs with a CWE classification | 86/100 (86%) |
| Intelligence generation without error | 100/100 (100%) |
| CVEs with ≥1 inferred ATT&CK mapping | 6/100 (6%) — zero unsupported mappings observed |
| CVEs receiving mitigation guidance | 100/100 (100%) |
| Average analysis confidence | 0.86 (range 0.65–0.90, directly tied to data completeness) |

The low (6%) ATT&CK mapping rate is an intended consequence of the precision-over-coverage design (Section 5.2), not a shortfall — every mapping produced was independently traceable to a specific descriptive phrase in its source CVE. The 100% pipeline-reliability figure is direct empirical confirmation that the system handles real-world data variability (missing CVSS/CWE fields present in 14–17% of the batch) without failure, including the exact code path (`build_intelligence()`) that previously contained the session-identity-map bug documented in Section 5.4.

Additionally, this project's own local PostgreSQL deployment surfaced one further real-world robustness gap during testing: a legacy row inserted during an early manual database exercise (predating the stricter CVE ID validation pattern introduced later) caused an unhandled `500` error when the search endpoint attempted to validate it for a response. The fix — validating stored rows the same way inbound NVD data is validated, and skipping (with a logged warning) any row that fails, rather than failing the entire response — is a direct, concrete instance of the "never blindly trust data, even your own" principle applied one layer further than originally scoped.

---

## 10. Limitations and Future Work

- **ATT&CK catalogue breadth**: five techniques, chosen for high-precision inference. Expanding coverage requires the same signal-based discipline per new technique, or integrating a genuinely curated (e.g. CAPEC-sourced) official-mapping dataset — the schema (`mapping_type: "official"`) already supports this without migration.
- **AI analysis engine**: deterministic by design today; a future LLM-backed implementation has a documented, tested prompt-injection-aware seam (`services/prompts.py`) but would require an additional output-validation layer to preserve the current groundedness guarantee, since that guarantee currently comes from construction rather than verification.
- **Horizontal scaling**: the rate limiter and background scheduler are single-process designs; a multi-instance deployment would need shared rate-limit storage and a dedicated ingestion worker rather than per-instance scheduling.
- **Dashboard authentication UX**: supports supplying an API key (added during this evaluation phase), stored in `sessionStorage` for the current tab only — a reasonable MVP tradeoff, not a full credential-management solution.

---

## 11. References

- National Vulnerability Database, CVE API 2.0 — https://nvd.nist.gov/developers/vulnerabilities
- MITRE ATT&CK, Enterprise Matrix — https://attack.mitre.org/matrices/enterprise/
- OWASP, Top Ten — https://owasp.org/www-project-top-ten/
- FastAPI documentation — https://fastapi.tiangolo.com/
- SQLAlchemy 2.0 documentation — https://docs.sqlalchemy.org/
- Pydantic documentation — https://docs.pydantic.dev/

See the day-by-day development log (`../docs/Day01.md` – `Day30.md`) for the complete implementation narrative, including all code excerpts, testing evidence, and reflective analysis this chapter summarizes.
