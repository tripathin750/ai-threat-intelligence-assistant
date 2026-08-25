# Sequence: `POST /intelligence/{cve_id}/analyze`

The request flow for the project's core feature — generating (or regenerating) a full, evidence-labelled intelligence record for one CVE. This is the current flow, including the optional LLM path (`services/llm_service.py`) — see [llm-decision-flow.md](llm-decision-flow.md) for what happens inside `generate_analysis()` itself.

```mermaid
sequenceDiagram
    actor User as Client (dashboard/API caller)
    participant API as FastAPI (main.py)
    participant Sec as Security middleware
    participant Intel as intelligence_service
    participant LLM as llm_service.generate_analysis()
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
        Intel->>LLM: generate_analysis(vulnerability)
        Note over LLM: Gemini if enabled + configured,<br/>else (or on any failure) the<br/>deterministic rules-based analyser.<br/>Either path returns the same shape:<br/>AnalysisResult (summary, impact, risk,<br/>confidence, evidence, attack_techniques,<br/>mitigations, model)
        LLM-->>Intel: AnalysisResult
        alt result.model starts with "gemini:"
            Note over Intel: use the LLM's own attack_techniques<br/>and mitigations directly (filtered against<br/>the known ATT&CK catalogue) — an empty<br/>list means "confidently found nothing",<br/>not "fall back to keyword matching"
        else deterministic path ran
            Intel->>ATT: infer_attack_techniques(vulnerability)
            ATT-->>Intel: [InferredTechnique...] (possibly empty)
            Intel->>MIT: recommend_mitigations(vulnerability, technique_ids)
            MIT-->>Intel: MitigationResult
        end
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
