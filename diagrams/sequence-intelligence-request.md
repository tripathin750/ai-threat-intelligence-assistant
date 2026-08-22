# Sequence: `POST /intelligence/{cve_id}/analyze`

The request flow for the project's core feature — generating (or regenerating) a full, evidence-labelled intelligence record for one CVE.

```mermaid
sequenceDiagram
    actor User as Client (dashboard/API caller)
    participant API as FastAPI (main.py)
    participant Sec as Security middleware
    participant Intel as intelligence_service
    participant AI as ai_service
    participant ATT as attack_service
    participant MIT as mitigation_service
    participant DB as PostgreSQL/SQLite

    User->>Sec: POST /intelligence/CVE-XXXX-YYYY/analyze
    Sec->>Sec: rate limit check
    Sec->>Sec: verify_api_key (if configured)
    Sec->>API: request passed through
    API->>DB: SELECT Vulnerability WHERE cve_id = ?
    alt CVE not found
        API-->>User: 404 Not Found
    else CVE found
        API->>Intel: build_intelligence(db, vulnerability, refresh=True)
        Intel->>AI: analyse_vulnerability(vulnerability)
        AI-->>Intel: AnalysisResult (summary, impact, risk, confidence, evidence)
        Intel->>ATT: infer_attack_techniques(vulnerability)
        ATT-->>Intel: [InferredTechnique...] (possibly empty)
        Intel->>MIT: recommend_mitigations(vulnerability, technique_ids)
        MIT-->>Intel: MitigationResult
        Intel->>DB: upsert IntelligenceAnalysis
        Intel->>DB: delete + reinsert VulnerabilityAttackMapping rows
        Intel->>DB: upsert MitigationRecommendation
        Intel->>DB: COMMIT
        Intel->>DB: re-query with populate_existing() + joinedload
        DB-->>Intel: hydrated Vulnerability + relations
        Intel-->>API: IntelligenceResponseSchema
        API-->>User: 200 OK, JSON (cve, analysis, attack_mappings[], mitigations, disclaimer)
    end
```

**Why `populate_existing()` matters here** (see [docs/Day21.md](../docs/Day21.md)): the existence check inside `build_intelligence()` reads `vulnerability.analysis` *before* the generate step runs, which can cache a stale `None` on the SQLAlchemy session's identity-mapped object. Without forcing the final query to refresh already-loaded relationship attributes, the response could incorrectly reflect pre-generation state even though the commit above it succeeded.
